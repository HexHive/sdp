#!/bin/bash
# One evaluation session. The prebuilt tree is mounted read-only so any number of
# sessions can share it; everything the run writes goes to workdir/<name>.
#
#   ./new_session.sh                       # session "default", sdp-eval
#   ./new_session.sh alice                 # a second, independent session
#   IMAGE=sdp-build ./new_session.sh mine  # the image that compiles; /sdp rw
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
name=${1:-default}
image=${IMAGE:-sdp-eval}
# Only the build image needs to write to the tree; eval sessions never do.
[ "$image" = sdp-build ] && mode=rw || mode=ro
work=$root/workdir/$name
mkdir -p "$work"
[ -t 0 ] && tty=(-it) || tty=(-i)

# Which uid the session runs as, so that what it writes belongs to you either way:
# under a rootless daemon the container's root is already your uid on the host,
# and asking for your uid inside would instead land in your subuid range, where
# nothing you own is writable. Under a rootful daemon it is the other way round.
if docker info -f '{{range .SecurityOptions}}{{.}} {{end}}' 2>/dev/null | grep -q rootless; then
	user=0:0
else
	user="$(id -u):$(id -g)"
fi

# ssh needs a passwd entry for the uid it runs as, and HOME has to be writable.
printf 'root:x:0:0:root:/work:/bin/bash\nsdp:x:%s:%s:sdp:/work:/bin/bash\n' \
	"$(id -u)" "$(id -g)" > "$work/passwd"

exec docker run --rm "${tty[@]}" \
	--name "sdp-$name" \
	--user "$user" \
	-v "$root:/sdp:$mode" \
	-v "$work:/work" \
	-v "$work/passwd:/etc/passwd:ro" \
	-e HOME=/work \
	-w /sdp \
	"$image:latest" "${@:2}"
