#!/usr/bin/env sh
# The DEFAULT computer-use backing (ADR-0007): a fully host-isolated Linux container.
# Use as the aiueos backing command — aiueos spawns it and pipes the computer-use ABI:
#
#   AIUEOS_COMPUTER_BACKING="examples/computer/backing/run.sh" \
#   AIUEOS_COMPUTER_URL="https://isekai.network/gftd/orbs" \
#     aiueos run examples/computer/drive.edn --policy examples/computer/policy.edn --surface computer-virtual
#
# Frames land in ./out on the host (mounted to /out in the container). The container
# has no host display or HID — the operator's machine is never driven.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${AIUEOS_COMPUTER_OUT:-$PWD/out}"
IMAGE="${AIUEOS_COMPUTER_IMAGE:-aiueos-computer-virtual}"
mkdir -p "$OUT"
# Build on first use if the image is missing.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" "$DIR" >&2
fi
exec docker run --rm -i --init \
  -e AIUEOS_COMPUTER_URL \
  -v "$OUT:/out" \
  "$IMAGE"
