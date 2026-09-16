#!/bin/sh
set -eu

if [ $# -eq 0 ]; then
    exec python /app/src/main.py
fi

case "$1" in
    inspect)
        shift
        exec python /app/src/main.py "$@"
        ;;
    probe)
        shift
        exec python /app/src/probe.py "$@"
        ;;
    serve|classify|-h|--help)
        exec python /app/src/classify.py "$@"
        ;;
    *)
        exec python /app/src/classify.py classify "$@"
        ;;
esac
