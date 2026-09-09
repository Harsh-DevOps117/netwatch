package capture

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type PacketReader interface {
	Packets() <-chan gopacket.Packet
	Close() error
}

type Handle struct {
	file   *os.File
	source *gopacket.PacketSource
}

func OpenPCAP(path string) (*Handle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %w", err)
	}

	pcapReader, err := pcapgo.NewReader(file)
	if err == nil {
		source := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
		return &Handle{file: file, source: source}, nil
	}

	if _, seekErr := file.Seek(0, io.SeekStart); seekErr == nil {
		ngReader, ngErr := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
		if ngErr == nil {
			source := gopacket.NewPacketSource(ngReader, ngReader.LinkType())
			return &Handle{file: file, source: source}, nil
		}
	}

	_ = file.Close()
	return nil, fmt.Errorf("failed to parse file %q as PCAP or PCAP-NG: %w", path, err)
}

func (h *Handle) Packets() <-chan gopacket.Packet {
	return h.source.Packets()
}

func (h *Handle) NextPacket() (gopacket.Packet, error) {
	return h.source.NextPacket()
}

func (h *Handle) Close() error {
	if h.file != nil {
		return h.file.Close()
	}
	return nil
}
