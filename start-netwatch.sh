#!/usr/bin/env bash
# Install Netwatch's Unix prerequisites, start capture + both model services,
# then open the interactive Go CLI. No frontend or dashboard is started.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$ROOT/artifacts/runtime"
LOGS="$RUNTIME/logs"
PIDS="$RUNTIME/pids"
CAPTURE="$RUNTIME/capture"
PYTHON="$ROOT/.venv/bin/python"
CLI="$RUNTIME/netwatch"
INTERFACE=""
DEVICE="cuda"
SKIP_SETUP=0
MODEL_ACCOUNT="kaustuk000"
MODEL_REVISION="v1.0.0"
OS="$(uname -s)"
ORIGINAL_ARGS=("$@")

usage() {
  printf '%s\n' \
    'Usage: bash ./start-netwatch.sh [--interface eth0] [--skip-setup]' \
    '       [--device cuda|cpu] [--model-account account] [--model-revision tag]' \
    'Installs every dependency (system tools, Go, JDK 8, uv + Python packages,' \
    'CICFlowMeter, the published model), starts capture/detection/forecast, then opens the CLI.' \
    'The frontend and dashboard are not started.'
}

while (($#)); do
  case "$1" in
    --interface|--device|--model-account|--model-revision)
      (($# >= 2)) || { printf 'Missing value for %s\n' "$1" >&2; exit 2; }
      case "$1" in
        --interface) INTERFACE="$2" ;;
        --device) DEVICE="$2" ;;
        --model-account) MODEL_ACCOUNT="$2" ;;
        --model-revision) MODEL_REVISION="$2" ;;
      esac
      shift 2 ;;
    --skip-setup) SKIP_SETUP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

step() { printf '\n%s  %s\n' "$1" "$2"; }
ok() { printf '✅ %s\n' "$*"; }
warn() { printf '⚠️  %s\n' "$*" >&2; }
die() { printf '❌ Netwatch: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing $1; re-run without --skip-setup"; }
admin() { command -v sudo >/dev/null 2>&1 || die 'sudo is required to install system packages'; sudo "$@"; }

if [[ "$OS" != Linux && "$OS" != Darwin ]]; then
  die 'This launcher supports Linux and macOS. On Windows use start-netwatch.cmd.'
fi
if (( EUID == 0 )); then
  die 'Run as your normal user, not with sudo. The script requests sudo only for system packages.'
fi

ensure_brew() {
  command -v brew >/dev/null 2>&1 && return 0
  (( SKIP_SETUP == 0 )) || die 'Homebrew is missing; re-run without --skip-setup'
  step 🍺 'Installing Homebrew'
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  local brew_bin
  for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [[ -x "$brew_bin" ]]; then eval "$("$brew_bin" shellenv)"; fi
  done
  need brew
}

install_system_tools() {
  local missing=()
  command -v git >/dev/null 2>&1 || missing+=(git)
  command -v go >/dev/null 2>&1 || missing+=(go)
  command -v tshark >/dev/null 2>&1 || missing+=(tshark)
  command -v dumpcap >/dev/null 2>&1 || missing+=(dumpcap)
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  if [[ "$OS" == Linux ]]; then command -v python3 >/dev/null 2>&1 || missing+=(python3); fi
  ((${#missing[@]})) || { ok 'System tools already installed'; return 0; }
  (( SKIP_SETUP == 0 )) || die "missing tools: ${missing[*]}"
  step 📦 "Installing system tools: ${missing[*]}"
  if [[ "$OS" == Darwin ]]; then
    ensure_brew
    local packages=()
    command -v git >/dev/null 2>&1 || packages+=(git)
    command -v go >/dev/null 2>&1 || packages+=(go)
    if ! command -v tshark >/dev/null 2>&1 || ! command -v dumpcap >/dev/null 2>&1; then packages+=(wireshark); fi
    command -v curl >/dev/null 2>&1 || packages+=(curl)
    brew install "${packages[@]}"
  elif command -v apt-get >/dev/null 2>&1; then
    # Answer wireshark-common's "may non-root users capture?" prompt up front.
    printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean true' | admin debconf-set-selections
    admin apt-get update
    admin env DEBIAN_FRONTEND=noninteractive apt-get install -y git golang-go tshark wireshark-common curl ca-certificates python3
  elif command -v dnf >/dev/null 2>&1; then
    admin dnf install -y git golang wireshark-cli curl ca-certificates python3
  elif command -v pacman >/dev/null 2>&1; then
    admin pacman -S --needed git go wireshark-cli curl ca-certificates python
  else
    die 'Unsupported Linux package manager. Install git, Go 1.21+, tshark, dumpcap, curl, and JDK 8, then use --skip-setup.'
  fi
  ok 'System tools installed'
}

# dumpcap is usually root:wireshark with capture capabilities, so a fresh
# install cannot capture until the user is in that group.
ensure_capture_access() {
  [[ "$OS" == Linux ]] || return 0
  dumpcap -D >/dev/null 2>&1 && return 0
  (( SKIP_SETUP == 0 )) || die "dumpcap cannot capture as $USER; re-run without --skip-setup"
  step 🔐 'Granting packet-capture access'
  if command -v dpkg-reconfigure >/dev/null 2>&1; then
    printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean true' | admin debconf-set-selections
    admin env DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
  fi
  getent group wireshark >/dev/null || die 'No wireshark group; give dumpcap capture rights manually, then re-run'
  if ! id -nG "$USER" | grep -qw wireshark; then
    admin usermod -aG wireshark "$USER"
    ok "Added $USER to the wireshark group"
  fi
  [[ -z "${NETWATCH_REEXEC:-}" ]] || die 'dumpcap still cannot capture after joining the wireshark group; check: dumpcap -D'
  warn 'Group change needs a new login to stick; continuing this run under the wireshark group.'
  export NETWATCH_REEXEC=1
  exec sg wireshark -c "$(printf '%q ' bash "$ROOT/start-netwatch.sh" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"})"
}

use_java8() {
  local home_dir="" candidate
  if [[ "$OS" == Darwin ]]; then
    home_dir="$(/usr/libexec/java_home -v 1.8 2>/dev/null || true)"
  else
    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/javac" ]]; then
      candidate="$JAVA_HOME/bin/javac"
      if "$candidate" -version 2>&1 | grep -Eq '^javac (1\.8\.|8\.)'; then home_dir="$JAVA_HOME"; fi
    fi
    if [[ -z "$home_dir" ]]; then
      for candidate in /usr/lib/jvm/temurin-8* /usr/lib/jvm/java-8-openjdk* /usr/lib/jvm/java-1.8.0-openjdk*; do
        if [[ -x "$candidate/bin/javac" ]]; then home_dir="$candidate"; break; fi
      done
    fi
  fi
  if [[ -n "$home_dir" && -x "$home_dir/bin/javac" ]]; then
    export JAVA_HOME="$home_dir"
    export PATH="$JAVA_HOME/bin:$PATH"
  fi
  command -v javac >/dev/null 2>&1 && javac -version 2>&1 | grep -Eq '^javac (1\.8\.|8\.)'
}

install_java8() {
  if use_java8; then ok 'JDK 8 already installed'; return 0; fi
  (( SKIP_SETUP == 0 )) || die 'JDK 8 is required by CICFlowMeter; re-run without --skip-setup'
  step ☕ 'Installing JDK 8 for CICFlowMeter'
  if [[ "$OS" == Darwin ]]; then
    ensure_brew
    brew install --cask temurin@8
  elif command -v apt-get >/dev/null 2>&1; then
    if apt-cache show openjdk-8-jdk >/dev/null 2>&1; then
      admin apt-get install -y openjdk-8-jdk
    else
      admin apt-get install -y curl ca-certificates gpg apt-transport-https
      if [[ ! -f /usr/share/keyrings/adoptium.gpg ]]; then
        curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public |
          gpg --dearmor | admin tee /usr/share/keyrings/adoptium.gpg >/dev/null
      fi
      if [[ ! -f /etc/apt/sources.list.d/adoptium.list ]]; then
        local codename
        # shellcheck disable=SC1091
        . /etc/os-release
        codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
        [[ -n "$codename" ]] || die 'Could not determine the distro codename for the Adoptium JDK 8 repository'
        printf 'deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb %s main\n' "$codename" |
          admin tee /etc/apt/sources.list.d/adoptium.list >/dev/null
      fi
      admin apt-get update
      admin apt-get install -y temurin-8-jdk
    fi
  elif command -v dnf >/dev/null 2>&1; then
    # Fedora 42+ dropped its own OpenJDK 8; Temurin 8 comes from the Adoptium repo it ships.
    admin dnf install -y java-1.8.0-openjdk-devel || {
      admin dnf install -y adoptium-temurin-java-repository
      admin dnf install -y --enablerepo=adoptium-temurin-java-repository temurin-8-jdk
    }
  elif command -v pacman >/dev/null 2>&1; then
    admin pacman -S --needed jdk8-openjdk
  fi
  use_java8 || die 'JDK 8 was installed but is not available; set JAVA_HOME to its installation and re-run'
  ok "JDK 8 installed ($JAVA_HOME)"
}

install_uv() {
  export PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$HOME/.local/bin:$PATH"
  if command -v uv >/dev/null 2>&1; then ok "$(uv --version) already installed"; return 0; fi
  (( SKIP_SETUP == 0 )) || die 'uv is missing; re-run without --skip-setup'
  need curl
  step 🐍 'Installing uv (Python package manager)'
  curl -LsSf https://astral.sh/uv/install.sh | sh
  command -v uv >/dev/null 2>&1 || die 'uv installed but is not on PATH; open a new shell and re-run'
  ok "$(uv --version) installed"
}

check_go() {
  local version major minor
  version="$(go version)"
  if [[ "$version" =~ go([0-9]+)\.([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"
    if (( major > 1 || (major == 1 && minor >= 21) )); then ok "Go $major.$minor already installed"; return 0; fi
  fi
  (( SKIP_SETUP == 0 )) || die "Go 1.21+ is required; found: $version"
  step 🐹 "Upgrading Go (found: $version)"
  if [[ "$OS" == Darwin ]]; then
    ensure_brew
    brew upgrade go || brew install go
    version="$(go version)"
    [[ "$version" =~ go([0-9]+)\.([0-9]+) ]] &&
      (( BASH_REMATCH[1] > 1 || (BASH_REMATCH[1] == 1 && BASH_REMATCH[2] >= 21) )) && return 0
    die "Go is still too old after the Homebrew upgrade: $version"
  fi
  # Distro packages can be older than cli/go.mod. Fetch the latest stable
  # official Linux archive, verify its published SHA-256, and keep it local.
  need python3
  local arch release filename checksum temp_dir target selection
  case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die 'Go auto-install supports Linux x86_64 and arm64 only' ;; esac
  selection="$(
    curl -fsSL 'https://go.dev/dl/?mode=json' |
      python3 -c 'import json,sys; r=json.load(sys.stdin)[0]; f=next(x for x in r["files"] if x["os"]=="linux" and x["arch"]==sys.argv[1] and x["kind"]=="archive"); print(r["version"], f["filename"], f["sha256"])' "$arch"
  )" || die 'Could not read official Go release metadata'
  read -r release filename checksum <<<"$selection"
  [[ -n "${release:-}" && -n "${filename:-}" && -n "${checksum:-}" ]] || die 'Could not resolve an official Go archive'
  target="$RUNTIME/tools/$release"
  if [[ ! -x "$target/bin/go" ]]; then
    [[ ! -e "$target" ]] || die "Incomplete Go install at $target; move it aside and re-run"
    mkdir -p "$RUNTIME/tools"
    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/netwatch-go.XXXXXX")"
    curl -fL "https://go.dev/dl/$filename" -o "$temp_dir/$filename"
    printf '%s  %s\n' "$checksum" "$temp_dir/$filename" | sha256sum -c -
    tar -xzf "$temp_dir/$filename" -C "$temp_dir"
    mv "$temp_dir/go" "$target"
    rm -f -- "$temp_dir/$filename"
    rmdir -- "$temp_dir"
  fi
  export PATH="$target/bin:$PATH"
  ok "Using $(go version)"
}

setup_models() {
  if (( SKIP_SETUP == 0 )); then
    step 🐍 'Syncing Python dependencies (first run downloads PyTorch, this takes a while)'
    uv sync --frozen
    ok 'Python environment ready'
    step 🔨 'Building CICFlowMeter'
    local flow_dir="$ROOT/tools/CICFlowMeter" flow_commit
    if [[ ! -f "$flow_dir/gradlew" ]]; then git submodule update --init tools/CICFlowMeter; fi
    [[ -f "$flow_dir/gradlew" ]] || die 'CICFlowMeter submodule is missing'
    flow_commit="$(git -C "$flow_dir" rev-parse HEAD)"
    [[ "$flow_commit" == acaf8bea8611fb4b996b4d33964dfd9155d9efdf ]] ||
      die "CICFlowMeter is at $flow_commit, not its pinned setup commit; preserve local changes before restoring it"
    ( cd "$flow_dir" && bash ./gradlew -q -I "$ROOT/tools/repo/cicflowmeter.gradle" compileJava -PpcapDir=- -PoutputDir=- )
    ok 'CICFlowMeter built'
    if [[ ! -e "$ROOT/artifacts/current" && ! -L "$ROOT/artifacts/current" ]]; then
      step 🧠 "Downloading model $MODEL_ACCOUNT/netwatch-flow-cascade@$MODEL_REVISION"
      uv run --frozen --with huggingface_hub python tools/publish/download.py \
        --repo "$MODEL_ACCOUNT/netwatch-flow-cascade" --revision "$MODEL_REVISION"
      local downloaded="$ROOT/artifacts/huggingface/download/netwatch-flow-cascade"
      [[ -f "$downloaded/serving.json" ]] || die 'Downloaded model has no serving.json; check access to the published release'
      ln -s 'huggingface/download/netwatch-flow-cascade' "$ROOT/artifacts/current"
    fi
  fi
  # Upstream commits gradlew without the execute bit, and the services run ./gradlew directly.
  chmod +x "$ROOT/tools/CICFlowMeter/gradlew"
  [[ -x "$PYTHON" ]] || die 'Python environment missing; re-run without --skip-setup'
  local item
  for item in flow_encoder.pt detection_encoder.pt forecasting_encoder.pt compressor.pt world_model.pt serving.json; do
    [[ -f "$ROOT/artifacts/current/$item" ]] || die "Model checkpoint missing: artifacts/current/$item"
  done
  compgen -G "$ROOT/artifacts/current/detector/head_*.pt" >/dev/null || die 'No detector heads in artifacts/current/detector'
  ok 'Model checkpoints present'
}

select_interface() {
  if [[ -z "$INTERFACE" ]]; then
    if [[ "$OS" == Linux ]] && command -v ip >/dev/null 2>&1; then
      INTERFACE="$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    elif [[ "$OS" == Darwin ]]; then
      INTERFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2;exit}')"
    fi
  fi
  [[ -n "$INTERFACE" ]] || die 'Could not detect an interface. Re-run with --interface NAME (see: tshark -D).'
  local devices
  devices="$(tshark -D 2>&1)" || die "Cannot list capture devices. Configure dumpcap capture permissions first. Details: $devices"
  grep -Fq -- "$INTERFACE" <<<"$devices" || die "Interface '$INTERFACE' not found. Available devices: $devices"
  ok "Capture interface: $INTERFACE"
}

# jnetpcap (CICFlowMeter's reader, used by forecast) links against the unversioned
# libpcap.so, which only -dev packages ship. Point it at the runtime library
# that tshark already depends on, so no extra system package is needed.
ensure_libpcap_link() {
  [[ "$OS" == Linux ]] || return 0
  local libs lib
  libs="$(PATH="$PATH:/sbin:/usr/sbin" ldconfig -p)"
  grep -q 'libpcap\.so ' <<<"$libs" && return 0
  lib="$(awk '/libpcap\.so\.[0-9]/ {print $NF; exit}' <<<"$libs")"
  [[ -n "$lib" ]] || die 'libpcap is not installed; install your distro libpcap package and re-run'
  mkdir -p "$RUNTIME/lib"
  ln -sf "$lib" "$RUNTIME/lib/libpcap.so"
  export LD_LIBRARY_PATH="$RUNTIME/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  ok "libpcap.so linked to $lib for CICFlowMeter"
}

start_service() {
  local name="$1" signature="$2" pid_file pid existing attempt
  shift 2
  pid_file="$PIDS/$name.pid"
  if [[ -f "$pid_file" ]]; then
    read -r pid < "$pid_file" || true
    if [[ "${pid:-}" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      existing="$(ps -p "$pid" -o args= 2>/dev/null || true)"
      if [[ "$existing" == *"$signature"* ]]; then
        ok "$name already running (PID $pid)"
        grep -m1 'Running in ' "$LOGS/$name.out.log" || true
        return 0
      fi
    fi
  fi
  nohup "$@" >"$LOGS/$name.out.log" 2>"$LOGS/$name.err.log" </dev/null &
  pid=$!
  printf '%s\n' "$pid" > "$pid_file"
  sleep 2
  if ! kill -0 "$pid" 2>/dev/null; then
    printf '❌ %s failed to start; last log lines:\n' "$name" >&2
    tail -n 15 "$LOGS/$name.err.log" >&2 || true
    die 'Check capture permissions, interface, model files, and the log above.'
  fi
  ok "$name started (PID $pid)"
  if [[ "$name" == detection || "$name" == forecast ]]; then
    for ((attempt=0; attempt<30; attempt++)); do
      if grep -m1 'Running in ' "$LOGS/$name.out.log"; then return 0; fi
      if ! kill -0 "$pid" 2>/dev/null; then
        tail -n 15 "$LOGS/$name.err.log" >&2 || true
        die "$name failed while loading models"
      fi
      sleep 1
    done
    warn "$name is still loading; check $LOGS/$name.out.log for its verified device."
  fi
}

cd "$ROOT"
printf '\n🛡️  Netwatch launcher (%s)\n' "$OS"
install_system_tools
need git; need go; need tshark; need dumpcap; need curl
ensure_capture_access
check_go
install_java8
install_uv
setup_models
"$PYTHON" -m models.serving.device --device "$DEVICE"
select_interface
SAFE_INTERFACE="${INTERFACE//[^[:alnum:]_-]/_}"
CAPTURE="$RUNTIME/capture-$SAFE_INTERFACE"
FORECAST_WORK="$RUNTIME/forecast-$SAFE_INTERFACE"
INTERFACE_STATE="$RUNTIME/capture-interface.txt"
DEVICE_STATE="$RUNTIME/model-device.txt"
previous_device=""
[[ ! -f "$DEVICE_STATE" ]] || read -r previous_device < "$DEVICE_STATE" || true
previous_interface=""
[[ ! -f "$INTERFACE_STATE" ]] || read -r previous_interface < "$INTERFACE_STATE" || true
if [[ -z "$previous_interface" && -f "$PIDS/detection.pid" ]]; then
  read -r old_detector_pid < "$PIDS/detection.pid" || true
  if [[ "${old_detector_pid:-}" =~ ^[0-9]+$ ]]; then
    old_detector_args="$(ps -p "$old_detector_pid" -o args= 2>/dev/null || true)"
    if [[ "$old_detector_args" == *models.serving.detect_live* &&
          "$old_detector_args" != *"--interface $INTERFACE"* ]]; then
      previous_interface="previous selection"
    fi
  fi
fi
if [[ ( -n "$previous_interface" && "$previous_interface" != "$INTERFACE" ) || "$previous_device" != "$DEVICE" ]]; then
  step 🔄 "Restarting this checkout's services for interface $INTERFACE and device $DEVICE"
  for service in detection forecast capture; do
    pid_file="$PIDS/$service.pid"
    [[ -f "$pid_file" ]] || continue
    read -r pid < "$pid_file" || continue
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    [[ "$args" == *"$ROOT"* ]] || continue
    kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 2
  for service in detection forecast capture; do
    pid_file="$PIDS/$service.pid"
    [[ -f "$pid_file" ]] || continue
    read -r pid < "$pid_file" || continue
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null &&
       [[ "$(ps -p "$pid" -o args= 2>/dev/null || true)" == *"$ROOT"* ]]; then
      die "Old $service process $pid did not stop; stop it manually before switching interfaces"
    fi
  done
fi
mkdir -p "$LOGS" "$PIDS" "$CAPTURE" "$RUNTIME/calibration" "$FORECAST_WORK"
ensure_libpcap_link
step 🔨 'Building Netwatch CLI'
( cd "$ROOT/cli" && go build -o "$CLI" . )
ok 'CLI built'

step 📡 'Starting capture, detection, and forecast (no frontend or dashboard)'
start_service capture "$CAPTURE" dumpcap -i "$INTERFACE" -F pcap -b duration:30 -b files:40 -w "$CAPTURE/live.pcap"
start_service detection models.serving.detect_live "$PYTHON" -u -m models.serving.detect_live \
  --interface "$INTERFACE" --device "$DEVICE" --port 8902 --live-calibration-hours 4 \
  --calibration-db "$RUNTIME/calibration/detection-4h-$SAFE_INTERFACE.sqlite" \
  --incident-db "$RUNTIME/incidents.sqlite"
start_service forecast models.serving.live "$PYTHON" -u -m models.serving.live \
  --input "$CAPTURE" --work "$FORECAST_WORK" --device "$DEVICE" --port 8901 \
  --live-calibration-hours 4 --calibration-db "$RUNTIME/calibration/world-4h-$SAFE_INTERFACE.sqlite"
printf '%s\n' "$INTERFACE" > "$INTERFACE_STATE"
printf '%s\n' "$DEVICE" > "$DEVICE_STATE"
printf '   Models requested on %s; verified device is reported in each service startup log.\n' "$DEVICE"

printf '\n🚀 Netwatch CLI ready. Type help, model, or exit. Logs: %s\n' "$LOGS"
printf '%s\n' '   Services continue in the background after the CLI exits.'
exec "$CLI" --config "$ROOT/cli/config.yaml"
