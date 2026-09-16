from __future__ import annotations

import asyncio
import hashlib
import json

from log import LEVELS, log, set_level
from profiles import DEFAULT_PROFILE, ProfileError, Registry, parse_profile

BUCKET = "WAF_DESIRED"
KEY = "policy/vlai"

RETRY_S = 5.0


def canon_hash(profiles: dict, settings: dict | None = None) -> str:
    digest = hashlib.sha256()
    for name in sorted(profiles):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        for file in profiles[name]:
            digest.update(str(file.get("name", "")).encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(file.get("text", "")).encode("utf-8"))
            digest.update(b"\0")
    if settings is not None:
        digest.update(b"settings\0log_level\0")
        digest.update(str(settings.get("log_level", "")).encode("utf-8"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def parse_settings(value: object) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProfileError("settings is not an object")
    level = value.get("log_level")
    if level not in LEVELS:
        raise ProfileError("settings.log_level: expected one of %s, got %r"
                           % (", ".join(LEVELS), level))
    return {"log_level": level}


def parse_manifest(raw: bytes) -> tuple[dict, int, str, dict | None]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError("manifest does not parse: %s" % exc) from exc

    if not isinstance(value, dict) or value.get("v") != 1:
        raise ProfileError("manifest is not v=1")

    profiles = value.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ProfileError("manifest has no profiles")

    files_of: dict = {}
    for name, row in profiles.items():
        files = row.get("files") if isinstance(row, dict) else None
        if not isinstance(files, list) or not files:
            raise ProfileError("profile %r has no files" % name)
        files_of[name] = files

    rev = value.get("rev")
    config_hash = value.get("config_hash")
    return (
        files_of,
        rev if isinstance(rev, int) else 0,
        config_hash if isinstance(config_hash, str) else "",
        parse_settings(value.get("settings")),
    )


def apply_manifest(registry: Registry, raw: bytes) -> bool:
    try:
        files_of, rev, declared, settings = parse_manifest(raw)

        parsed = {}
        for name, files in files_of.items():
            text = None
            for file in files:
                if file.get("name") == "profile.yaml":
                    text = str(file.get("text", ""))
                    break
            if text is None:
                raise ProfileError("profile %r has no profile.yaml" % name)
            parsed[name] = parse_profile(name, text)

        if DEFAULT_PROFILE not in parsed:
            raise ProfileError("generation has no %r profile" % DEFAULT_PROFILE)
    except ProfileError as exc:
        registry.reject_generation(str(exc))
        log("error", "vlai generation rejected", error=str(exc))
        return False

    actual = canon_hash(files_of, settings)
    if actual != declared:
        log("warn", "generation hash mismatch", declared=declared, actual=actual)

    registry.apply_generation(parsed, actual, rev)

    if settings is not None and set_level(settings["log_level"]):
        log("info", "log level applied", log_level=settings["log_level"])

    log(
        "info",
        "vlai generation applied",
        rev=rev,
        hash=actual,
        profiles=sorted(parsed),
    )
    return True


async def watch(nc, registry: Registry) -> None:
    js = nc.jetstream()

    while True:
        try:
            kv = await js.key_value(BUCKET)
        except Exception:  # noqa: BLE001
            await asyncio.sleep(RETRY_S)
            continue

        try:
            watcher = await kv.watch(KEY, include_history=False)
        except Exception as exc:  # noqa: BLE001
            log("warn", "desired watch failed", error=str(exc))
            await asyncio.sleep(RETRY_S)
            continue

        try:
            async for entry in watcher:
                if entry is None or entry.value is None:
                    continue
                if entry.operation in ("DEL", "PURGE"):
                    continue
                apply_manifest(registry, entry.value)
        except Exception as exc:  # noqa: BLE001
            log("warn", "desired watch interrupted", error=str(exc))
        finally:
            try:
                await watcher.stop()
            except Exception:  # noqa: BLE001
                pass

        await asyncio.sleep(RETRY_S)
