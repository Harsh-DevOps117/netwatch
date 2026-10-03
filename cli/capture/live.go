package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type LiveHandle struct {
	cmd           *exec.Cmd
	closeJob      func()
	source        *gopacket.PacketSource
	InterfaceName string
}

func (lh *LiveHandle) Interface() string {
	return lh.InterfaceName
}

// GetDefaultInterface determines the best active network interface.
// 1. Checks active routing outbound interface (UDP socket probe to external gateway / DNS).
// 2. Looks for an interface with an assigned non-loopback IP address, preferring active Wi-Fi / Ethernet.
// 3. Falls back to "any" if no specific active interface can be determined.
func GetDefaultInterface() string {
	// Strategy 1: Find interface used for outbound routing
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 200*time.Millisecond)
	if err == nil {
		localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		_ = conn.Close()
		if ok && localAddr != nil && !localAddr.IP.IsUnspecified() && !localAddr.IP.IsLoopback() {
			if ifaceName := findInterfaceByIP(localAddr.IP); ifaceName != "" {
				return ifaceName
			}
		}
	}

	// Strategy 2: Iterate over network interfaces and find the best active one with an assigned IP
	ifaces, err := net.Interfaces()
	if err == nil {
		var candidateWithIP string
		var wirelessCandidate string

		for _, iface := range ifaces {
			// Skip loopback or administratively down interfaces
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			hasValidIP := false
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
					hasValidIP = true
					break
				}
			}

			if hasValidIP {
				name := iface.Name
				if isWireless(name) {
					wirelessCandidate = name
				} else if candidateWithIP == "" {
					candidateWithIP = name
				}
			}
		}

		if candidateWithIP != "" {
			return candidateWithIP
		}
		if wirelessCandidate != "" {
			return wirelessCandidate
		}
	}

	return "any"
}

func findInterfaceByIP(targetIP net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(targetIP) {
				return iface.Name
			}
		}
	}
	return ""
}

func isWireless(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "wl") || strings.HasPrefix(lower, "wi")
}

// lookCaptureTool finds a capture tool in PATH, then in Wireshark's default
// Windows install directories, which its installer does not add to PATH.
func lookCaptureTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil || runtime.GOOS != "windows" {
		return path, err
	}
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432"), os.Getenv("ProgramFiles(x86)")} {
		if root == "" {
			continue
		}
		candidate := filepath.Join(root, "Wireshark", name+".exe")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", err
}

func tryOpenLive(iface string, bpfFilter string) (*LiveHandle, error) {
	var cmd *exec.Cmd

	tsharkPath, err := lookCaptureTool("tshark")
	if err == nil {
		args := []string{"-i", iface, "-F", "pcap", "-w", "-"}
		if bpfFilter != "" {
			args = append(args, "-f", bpfFilter)
		}
		cmd = exec.Command(tsharkPath, args...)
	} else {
		tcpdumpPath, tcpErr := lookCaptureTool("tcpdump")
		if tcpErr != nil {
			return nil, fmt.Errorf("neither 'tshark' nor 'tcpdump' was found in PATH for live capture. Please install tshark (Wireshark) or tcpdump")
		}
		args := []string{"-i", iface, "-w", "-", "-U", "-s", "0"}
		if bpfFilter != "" {
			args = append(args, bpfFilter)
		}
		cmd = exec.Command(tcpdumpPath, args...)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start live capture on interface %q: %w", iface, err)
	}
	closeJob, err := bindCaptureLifetime(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("failed to contain capture process on interface %q: %w", iface, err)
	}

	bufReader := bufio.NewReader(stdout)
	pcapReader, err := pcapgo.NewReader(bufReader)
	if err != nil {
		ngReader, ngErr := pcapgo.NewNgReader(bufReader, pcapgo.DefaultNgReaderOptions)
		if ngErr == nil {
			source := gopacket.NewPacketSource(ngReader, ngReader.LinkType())
			return &LiveHandle{cmd: cmd, closeJob: closeJob, source: source, InterfaceName: iface}, nil
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		closeJob()

		stderrStr := strings.TrimSpace(stderrBuf.String())
		if stderrStr != "" {
			return nil, fmt.Errorf("failed to initialize live packet stream on %q: %w (capture tool output: %s)", iface, err, stderrStr)
		}
		return nil, fmt.Errorf("failed to initialize live packet stream on %q: %w", iface, err)
	}

	source := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	return &LiveHandle{
		cmd:           cmd,
		closeJob:      closeJob,
		source:        source,
		InterfaceName: iface,
	}, nil
}

func OpenLive(iface string, bpfFilter string) (*LiveHandle, error) {
	isAuto := (iface == "" || iface == "auto")
	targetIface := iface
	if isAuto {
		targetIface = GetDefaultInterface()
	}

	handle, err := tryOpenLive(targetIface, bpfFilter)
	if err == nil {
		return handle, nil
	}

	// If auto-detection failed on the selected interface, attempt automatic fallback to "any"
	if isAuto && targetIface != "any" {
		fallbackHandle, fallbackErr := tryOpenLive("any", bpfFilter)
		if fallbackErr == nil {
			return fallbackHandle, nil
		}
	}

	errMsg := fmt.Sprintf("%v", err)
	if strings.Contains(strings.ToLower(errMsg), "permission") || strings.Contains(strings.ToLower(errMsg), "operation not permitted") || strings.Contains(strings.ToLower(errMsg), "you don't have permission") {
		return nil, fmt.Errorf("%w\n\n[!] TIP: Live packet capture requires root/administrator privileges. Run with 'sudo':\n    sudo go run . live -i %s", err, targetIface)
	}

	return nil, fmt.Errorf("%w\n\n[!] TIP: You can specify an active interface manually using '-i <interface>' (e.g. -i wlo1 or -i any), and ensure you run with 'sudo'.", err)
}

func (lh *LiveHandle) Packets() <-chan gopacket.Packet {
	return lh.source.Packets()
}

func (lh *LiveHandle) Close() error {
	if lh.cmd != nil && lh.cmd.Process != nil {
		_ = lh.cmd.Process.Kill()
		_ = lh.cmd.Wait()
	}
	if lh.closeJob != nil {
		lh.closeJob()
		lh.closeJob = nil
	}
	return nil
}

func OpenStdin() (*Handle, error) {
	bufReader := bufio.NewReader(os.Stdin)
	pcapReader, err := pcapgo.NewReader(bufReader)
	if err == nil {
		source := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
		return &Handle{file: nil, source: source}, nil
	}

	ngReader, ngErr := pcapgo.NewNgReader(bufReader, pcapgo.DefaultNgReaderOptions)
	if ngErr == nil {
		source := gopacket.NewPacketSource(ngReader, ngReader.LinkType())
		return &Handle{file: nil, source: source}, nil
	}

	return nil, fmt.Errorf("failed to parse standard input stream as PCAP or PCAP-NG: %w", err)
}
