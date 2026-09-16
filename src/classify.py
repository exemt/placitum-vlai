from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

DEFAULT_MODEL = "CIRCL/vulnerability-severity-classification-russian-ruRoberta-large"
DEFAULT_REVISION = "5de95b34808c905f912eb6fd11fdbd64717c57e3"
FALLBACK_LABELS = ("Low", "Medium", "High", "Critical")
MAX_LENGTH = 512

_tokenizer = None
_model = None
_labels: tuple[str, ...] = FALLBACK_LABELS
_revision: str | None = None
_model_id = DEFAULT_MODEL
_device = torch.device("cpu")


def _title(label: str) -> str:
    if not label:
        return label
    if label[:6].upper() == "LABEL_":
        try:
            return FALLBACK_LABELS[int(label[6:])]
        except (ValueError, IndexError):
            return label
    return label[:1].upper() + label[1:].lower()


def load(model_id: str, device: str, revision: str | None = None) -> None:
    global _tokenizer, _model, _labels, _revision, _model_id, _device
    _model_id = model_id
    _device = torch.device(device)
    if revision is None:
        revision = os.environ.get("VLAI_MODEL_REVISION") or (
            DEFAULT_REVISION if model_id == DEFAULT_MODEL else None
        )
    _tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision)
    _model = AutoModelForSequenceClassification.from_pretrained(model_id, revision=revision)
    _model.to(_device)
    _model.eval()
    raw = getattr(_model.config, "id2label", None) or {}
    if raw:
        _labels = tuple(_title(raw[i]) for i in range(len(raw)))
    else:
        _labels = FALLBACK_LABELS
    _revision = getattr(_model.config, "_commit_hash", None)


def classify(text: str) -> dict[str, Any]:
    if _model is None or _tokenizer is None:
        raise RuntimeError("model is not loaded")
    text = text.strip()
    if not text:
        return {
            "severity": None,
            "confidence": 0.0,
            "scores": {name: 0.0 for name in _labels},
            "model": _model_id,
            "model_revision": _revision,
            "error": "empty description",
        }
    inputs = _tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=MAX_LENGTH,
    )
    tokens = int(inputs["input_ids"].shape[1])
    truncated = False
    if tokens >= MAX_LENGTH:
        extra = _tokenizer(text, truncation=True, max_length=MAX_LENGTH + 1)
        truncated = len(extra["input_ids"]) > MAX_LENGTH
    inputs = {key: value.to(_device) for key, value in inputs.items()}
    with torch.no_grad():
        probs = torch.softmax(_model(**inputs).logits, dim=-1)[0]
    idx = int(probs.argmax())
    scores = {name: round(float(probs[i]), 4) for i, name in enumerate(_labels)}
    return {
        "severity": _labels[idx],
        "confidence": round(float(probs[idx]), 4),
        "scores": scores,
        "chars": len(text),
        "tokens": tokens,
        "truncated": truncated,
        "max_length": MAX_LENGTH,
        "device": str(_device),
        "model": _model_id,
        "model_revision": _revision,
    }


def _json_bytes(payload: dict[str, Any], status: int = 200) -> tuple[int, bytes]:
    body = json.dumps(payload, ensure_ascii=False, indent=None).encode("utf-8")
    return status, body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/health", "/healthz"):
            ready = _model is not None
            status, body = _json_bytes(
                {
                    "ok": ready,
                    "model": _model_id,
                    "revision": _revision,
                    "device": str(_device) if ready else None,
                },
                200 if ready else 503,
            )
            self._send(status, body)
            return
        if path in ("/", "/classify/severity"):
            status, body = _json_bytes(
                {
                    "service": "vlai",
                    "model": _model_id,
                    "model_revision": _revision,
                    "labels": list(_labels),
                    "post": "/classify/severity",
                }
            )
            self._send(status, body)
            return
        self._send(*_json_bytes({"error": "not found"}, 404))

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/classify/severity":
            self._send(*_json_bytes({"error": "not found"}, 404))
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(*_json_bytes({"error": "invalid json"}, 400))
            return
        if not isinstance(payload, dict):
            self._send(*_json_bytes({"error": "expected object"}, 400))
            return
        description = payload.get("description")
        if not isinstance(description, str):
            self._send(*_json_bytes({"error": "description must be a string"}, 400))
            return
        self._send(*_json_bytes(classify(description)))


def serve(host: str, port: int) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("vlai listening on http://%s:%d\n" % (host, port))
    httpd.serve_forever()


def _read_text(args: argparse.Namespace) -> str:
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vlai",
        description="Classify severity of a Russian vulnerability description.",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("VLAI_MODEL", DEFAULT_MODEL),
        help="Hugging Face model id (default: %(default)s)",
    )
    parser.add_argument(
        "--device",
        default=os.environ.get("VLAI_DEVICE", "cpu"),
        help="torch device (default: cpu)",
    )
    sub = parser.add_subparsers(dest="cmd")

    classify_p = sub.add_parser("classify", help="print JSON for one description")
    classify_p.add_argument("text", nargs="*", help="description; stdin if omitted")

    serve_p = sub.add_parser("serve", help="HTTP POST /classify/severity")
    serve_p.add_argument("--host", default=os.environ.get("VLAI_HOST", "0.0.0.0"))
    serve_p.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("VLAI_PORT", "8080")),
    )

    args = parser.parse_args(argv)
    load(args.model, args.device)

    if args.cmd == "serve" or args.cmd is None:
        host = getattr(args, "host", os.environ.get("VLAI_HOST", "0.0.0.0"))
        port = getattr(args, "port", int(os.environ.get("VLAI_PORT", "8080")))
        serve(host, port)
        return 0

    print(json.dumps(classify(_read_text(args)), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
