#!/bin/sh
# Fetch and build CICFlowMeter in tools/CICFlowMeter, a git submodule: the upstream repository at a pinned commit, plus
# the local Gradle overrides ingest needs (capture/output paths and the bundled jnetpcap library).
#
# Run once after cloning (git clone --recurse-submodules, or this script fetches it):   tools/setup_cicflowmeter.sh
# Needs git, a JDK 8 and, for the first build only, network access for Gradle's dependencies. Safe to re-run.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$REPO/tools/CICFlowMeter"
COMMIT=acaf8bea8611fb4b996b4d33964dfd9155d9efdf

# The submodule when the repository has it; a plain clone otherwise. `.git` is a file inside an initialised submodule.
[ -e "$DIR/.git" ] || git -C "$REPO" submodule update --init tools/CICFlowMeter 2>/dev/null \
	|| git clone https://github.com/UNBCIC/CICFlowMeter.git "$DIR"
cd "$DIR"
[ "$(git rev-parse HEAD)" = "$COMMIT" ] || git checkout -q "$COMMIT"

chmod +x gradlew
./gradlew -q -I "$REPO/tools/repo/cicflowmeter.gradle" compileJava -PpcapDir=- -PoutputDir=-
echo "CICFlowMeter ready in $DIR"
