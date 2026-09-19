#!/bin/bash
# The two images: sdp-eval runs the evaluation, sdp-build also compiles.
set -euo pipefail
cd -- "$(dirname -- "$0")"

for target in eval build; do
	echo "=== sdp-$target"
	docker build --target "$target" -t "sdp-$target:latest" .
done
docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' | grep '^sdp-'
