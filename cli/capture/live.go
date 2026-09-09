package capture

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type LiveHandle struct {
	cmd    *exec.Cmd
	source *gopacket.PacketSource
}

func GetDefaultInterface() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			return iface.Name
		}
	}
	return "any"
}

func OpenLive(iface string, bpfFilter string) (*LiveHandle, error) {
	if iface == "" || iface == "auto" {
		iface = GetDefaultInterface()
	}

	var cmd *exec.Cmd

	tsharkPath, err := exec.LookPath("tshark")
	if err == nil {
		args := []string{"-i", iface, "-F", "pcap", "-w", "-"}
		if bpfFilter != "" {
			args = append(args, "-f", bpfFilter)
		}
		cmd = exec.Command(tsharkPath, args...)
	} else {
		tcpdumpPath, tcpErr := exec.LookPath("tcpdump")
		if tcpErr != nil {
			return nil, fmt.Errorf("neither 'tshark' nor 'tcpdump' was found in PATH for live capture")
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
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start live capture on interface %q: %w", iface, err)
	}

	bufReader := bufio.NewReader(stdout)
	pcapReader, err := pcapgo.NewReader(bufReader)
	if err != nil {
		ngReader, ngErr := pcapgo.NewNgReader(bufReader, pcapgo.DefaultNgReaderOptions)
		if ngErr == nil {
			source := gopacket.NewPacketSource(ngReader, ngReader.LinkType())
			return &LiveHandle{cmd: cmd, source: source}, nil
		}
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("failed to initialize live packet stream on %q: %w", iface, err)
	}

	source := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	return &LiveHandle{
		cmd:    cmd,
		source: source,
	}, nil
}

func (lh *LiveHandle) Packets() <-chan gopacket.Packet {
	return lh.source.Packets()
}

func (lh *LiveHandle) Close() error {
	if lh.cmd != nil && lh.cmd.Process != nil {
		_ = lh.cmd.Process.Kill()
		_ = lh.cmd.Wait()
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
