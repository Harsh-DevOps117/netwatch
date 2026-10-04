#!/bin/sh
# Fetch and build CICFlowMeter in tools/CICFlowMeter, a git submodule: the upstream repository at a pinned commit, plus
# the local Gradle overrides ingest needs (capture/output paths and the bundled jnetpcap library).
#
# Run once after cloning (git clone --recurse-submodules, or this script fetches it):   tools/setup_cicflowmeter.sh
# Needs git, a JDK 8 (found on its own when it is not the active Java) and, for the first build only, network access
# for Gradle's dependencies. Safe to re-run.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$REPO/tools/CICFlowMeter"
COMMIT=acaf8bea8611fb4b996b4d33964dfd9155d9efdf

# The submodule when the repository has it; a plain clone otherwise. `.git` is a file inside an initialised submodule.
[ -e "$DIR/.git" ] || git -C "$REPO" submodule update --init tools/CICFlowMeter 2>/dev/null \
	|| git clone https://github.com/UNBCIC/CICFlowMeter.git "$DIR"
cd "$DIR"
[ "$(git rev-parse HEAD)" = "$COMMIT" ] || git checkout -q "$COMMIT"

# Its Gradle 4.2 wrapper runs on JDK 8 only. Keep the Java the wrapper would use when it is one; otherwise use a JDK 8
# from where the package managers put it, and say so instead of failing inside Gradle when there is none. `java` and
# `javac` are both checked: a machine can have javac 8 on its PATH beside a newer java.
is_jdk8() { [ -n "$1" ] && [ -x "$1/bin/java" ] && "$1/bin/javac" -version 2>&1 | grep -Eq '^javac (1\.8\.|8\.)'; }
on_jdk8() {
	"${JAVA_HOME:+$JAVA_HOME/bin/}java" -version 2>&1 | grep -Eq 'version "(1\.8\.|8\.)' &&
		"${JAVA_HOME:+$JAVA_HOME/bin/}javac" -version 2>&1 | grep -Eq '^javac (1\.8\.|8\.)'
}
if ! on_jdk8; then
	for home in "$(/usr/libexec/java_home -v 1.8 2>/dev/null || true)" \
			/usr/lib/jvm/temurin-8* /usr/lib/jvm/java-8-openjdk* /usr/lib/jvm/java-1.8.0-openjdk*; do
		if is_jdk8 "$home"; then
			JAVA_HOME="$home"; PATH="$home/bin:$PATH"; export JAVA_HOME PATH
			break
		fi
	done
	on_jdk8 || {
		echo "CICFlowMeter builds with JDK 8, and the active Java is $("${JAVA_HOME:+$JAVA_HOME/bin/}java" -version 2>&1 | head -n 1)."
		echo "Install a JDK 8 (for example Temurin 8) or point JAVA_HOME at one, then run this again."
		exit 1
	}
fi

chmod +x gradlew
./gradlew -q -I "$REPO/tools/repo/cicflowmeter.gradle" compileJava -PpcapDir=- -PoutputDir=-
echo "CICFlowMeter ready in $DIR"
