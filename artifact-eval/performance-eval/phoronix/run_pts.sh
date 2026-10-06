#!/usr/bin/env bash
# Run the Phoronix benchmarks of Paper §8.3 on the running kernel: the same tests,
# versions, and options as our earlier, less automated scripts (PTS v10.8.4).
# Copied with result_parse.py to ~/phoronix-test-suite on the board.
#
#   ./run_pts.sh <kernel>    # the name after "Linux 6.6-" in its GRUB entry, e.g. original
#
# PTS saves the run to ~/.phoronix-test-suite/test-results/<kernel>/; run again after
# an interruption, and it skips the tests already saved. Then ae_results.log is updated.

set -euo pipefail
cd "$(dirname "$0")"

# Each kernel's `uname -r`, so that a ~14 h run is not saved under the wrong name
KERNEL="${1:-}"
case "$KERNEL" in
  original)        RELEASE=6.6.0 ;;
  originalscs)     RELEASE=6.6.0-g292296b8210e-dirty ;;
  originalcfi)     RELEASE=6.6.0-g13cc6f2af7ba ;;
  originalscskcfi) RELEASE=6.6.0-00011-g4403f7c6618d-dirty ;;
  sdpsd)           RELEASE=6.6.0-g093980467686 ;;
  sdpret)          RELEASE=6.6.0-g540c9b035f86-dirty ;;
  sdpfp)           RELEASE=6.6.0-g363850efa265 ;;
  sdpfpifp)        RELEASE=6.6.0-ged0568986bfb ;;
  sdpretfp)        RELEASE=6.6.0-ge0fa8524ba5e ;;
  sdpsdretfp)      RELEASE=6.6.0-g456510093593 ;;
  cred)            RELEASE=6.6.0-g04d41bfdd80a ;;
  pagetable)       RELEASE=6.6.0-g94e6d7c53275 ;;
  credpagetable)   RELEASE=6.6.0-gfd0e330d8c4f ;;
  *) echo "usage: $0 <kernel>    # the name after \"Linux 6.6-\" in its GRUB entry" >&2; exit 1 ;;
esac
[ "$(uname -r)" = "$RELEASE" ] || { echo "not running Linux 6.6-$KERNEL: reboot into it" >&2; exit 1; }

TESTS=(
  pts/aio-stress-1.1.3
  pts/sqlite-2.3.0
  pts/dbench-1.0.2
  pts/iozone-1.9.6
  pts/tiobench-1.3.1
  pts/unpack-linux-1.2.0
  pts/postmark-1.1.2
  pts/ffmpeg-7.0.2
  pts/compress-7zip-1.12.0
  pts/build-linux-kernel-1.17.1
  pts/openssl-3.6.0
  pts/pgbench-1.17.0
  pts/apache-3.0.0
  pts/gnupg-2.5.0
)

# Options by their name in the test's menu
PRESETS=(
  "aio-stress.test=Random Write"
  "iozone.record-size=4Kb"
  "iozone.file-size=512MB"
  "iozone.test=Read Performance,Write Performance"
  "tiobench.test-item=Read,Write,Random Read,Random Write"
  "tiobench.filesize-per-thread=32MB"
  "ffmpeg.encoder=libx264"
  "ffmpeg.scenario=Live"
  "build-linux-kernel.build=defconfig"
  "openssl.algo=RSA4096"
  "pgbench.run-mode=Read Write"
)
# Options that are numbers, which PRESET_OPTIONS would take as a menu index
PRESET_VALUES=(
  "sqlite.cpu-threads=1"
  "dbench.client-count=1"
  "tiobench.thread-count=4"
  "pgbench.scaling-factor=1"
  "pgbench.clients=1"
  "apache.concurrent=4"
)
export PRESET_OPTIONS="$(IFS=';'; echo "${PRESETS[*]}")"
export PRESET_OPTIONS_VALUES="$(IFS=';'; echo "${PRESET_VALUES[*]}")"
export TEST_RESULTS_NAME="$KERNEL" TEST_RESULTS_IDENTIFIER="$KERNEL"

PTS=./phoronix-test-suite
[ -x "$PTS" ] || PTS=phoronix-test-suite

# Batch mode without prompts or uploads, taking the options above (batch-setup's
# default runs every option instead), and rerunning each test until its coefficient
# of variation is below 1% (Paper §8.3)
"$PTS" user-config-set SaveResults=TRUE OpenBrowser=FALSE UploadResults=FALSE \
  PromptForTestIdentifier=FALSE PromptForTestDescription=FALSE PromptSaveName=FALSE \
  RunAllTestCombinations=FALSE Configured=TRUE \
  DynamicRunCount=TRUE StandardDeviationThreshold=1 >/dev/null

# One test per call, so that a failing one does not stop the rest
for t in "${TESTS[@]}"; do
  "$PTS" batch-benchmark "$t" || echo "!!! $t failed"
done

python3 result_parse.py
