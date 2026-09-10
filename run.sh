#!/usr/bin/env bash
set -eo pipefail

# Netwatch - Deterministic Network Threat Detection Engine Runner
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="${SCRIPT_DIR}/cli"
BIN_DIR="${CLI_DIR}/bin"
BINARY="${BIN_DIR}/detector"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "================================================================================"
    echo "                 NETWATCH - THREAT DETECTION ENGINE RUNNER                      "
    echo "================================================================================"
    echo -e "${NC}"
}

check_go() {
    if ! command -v go &>/dev/null; then
        echo -e "${RED}[ERROR] Go is not installed or not found in PATH.${NC}"
        echo "Please install Go 1.21+ (https://golang.org/dl/) to build and run the engine."
        exit 1
    fi
}

build_binary() {
    mkdir -p "${BIN_DIR}"
    echo -e "${CYAN}[*] Building detector binary in ${CLI_DIR}...${NC}"
    (
        cd "${CLI_DIR}"
        go build -o "${BINARY}" main.go
    )
    echo -e "${GREEN}[✓] Build successful: ${BINARY}${NC}\n"
}

ensure_binary() {
    check_go
    # If binary doesn't exist, build it
    if [[ ! -f "${BINARY}" ]]; then
        build_binary
        return
    fi

    # Check if any .go source file is newer than the binary
    local newer_src
    newer_src=$(find "${CLI_DIR}" -name "*.go" -newer "${BINARY}" 2>/dev/null | head -n 1)
    if [[ -n "${newer_src}" ]]; then
        echo -e "${YELLOW}[!] Source files updated. Rebuilding detector...${NC}"
        build_binary
    fi
}

show_help() {
    print_header
    echo -e "${BOLD}USAGE:${NC}"
    echo -e "  ./run.sh <command> [options]"
    echo ""
    echo -e "${BOLD}COMMANDS:${NC}"
    echo -e "  ${GREEN}live${NC} [interface] [bpf]       Start real-time live network capture (auto-detects interface if omitted)"
    echo -e "  ${GREEN}analyze${NC} <pcap-file>          Analyze an offline PCAP / PCAP-NG packet capture file"
    echo -e "  ${GREEN}stdin${NC}                        Stream and parse PCAP telemetry from standard input pipe"
    echo -e "  ${GREEN}build${NC}                        Compile the detector binary"
    echo -e "  ${GREEN}clean${NC}                        Clean up compiled binaries and exported JSON reports"
    echo -e "  ${GREEN}help${NC}                         Show this help message"
    echo ""
    echo -e "${BOLD}OPTIONS & FLAGS:${NC}"
    echo -e "  ${YELLOW}-i, --interface <iface>${NC}      Specify network interface (e.g. eth0, wlo1, any)"
    echo -e "  ${YELLOW}-p, --pcap <file>${NC}            Path to PCAP file"
    echo -e "  ${YELLOW}-w, --window <seconds>${NC}       Time window aggregation slice (default: 10s)"
    echo -e "  ${YELLOW}-o, --output <file.json>${NC}     Export per-window feature vectors and alerts to JSON"
    echo -e "  ${YELLOW}-c, --config <config.yaml>${NC}   Path to custom YAML configuration file"
    echo -e "  ${YELLOW}-b, --bpf <expression>${NC}       BPF packet capture filter (e.g. 'tcp or udp')"
    echo ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo -e "  # 1. Start live monitoring on default interface:"
    echo -e "  ${CYAN}./run.sh live${NC}"
    echo ""
    echo -e "  # 2. Live monitoring on interface 'wlo1' with 5s window and JSON telemetry export:"
    echo -e "  ${CYAN}./run.sh live wlo1 -w 5 -o telemetry.json${NC}"
    echo ""
    echo -e "  # 3. Analyze an existing PCAP file:"
    echo -e "  ${CYAN}./run.sh analyze traffic.pcap${NC}"
    echo ""
    echo -e "  # 4. Stream from tshark / tcpdump directly through stdin:"
    echo -e "  ${CYAN}tshark -i eth0 -F pcap -w - | ./run.sh stdin${NC}"
    echo ""
}

# Main Execution Switch
case "${1:-}" in
    ""|"-h"|"--help"|"help")
        show_help
        exit 0
        ;;
    "build")
        check_go
        build_binary
        exit 0
        ;;
    "clean")
        echo -e "${CYAN}[*] Cleaning build artifacts and exported reports...${NC}"
        rm -rf "${BIN_DIR}" "${CLI_DIR}/*.pcap" "${CLI_DIR}/alerts.json" "${SCRIPT_DIR}/alerts.json"
        echo -e "${GREEN}[✓] Clean completed.${NC}"
        exit 0
        ;;
    "live")
        shift
        ensure_binary
        
        # Check if root/sudo is needed for live sniffing on Linux
        if [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null; then
            echo -e "${YELLOW}[!] Live packet sniffing requires root permissions. Elevating via sudo...${NC}"
            exec sudo "${BINARY}" live "$@"
        else
            exec "${BINARY}" live "$@"
        fi
        ;;
    "analyze")
        shift
        ensure_binary
        exec "${BINARY}" analyze "$@"
        ;;
    "stdin")
        shift
        ensure_binary
        exec "${BINARY}" --stdin "$@"
        ;;
    *)
        # Direct pass-through of flags (e.g., ./run.sh --pcap file.pcap or ./run.sh --live)
        ensure_binary
        if [[ "$*" == *"--live"* || "$*" == *"-l "* ]] && [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null; then
            echo -e "${YELLOW}[!] Live packet sniffing requires root permissions. Elevating via sudo...${NC}"
            exec sudo "${BINARY}" "$@"
        else
            exec "${BINARY}" "$@"
        fi
        ;;
esac
