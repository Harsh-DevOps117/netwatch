package capture

import (
	"net"
	"testing"
)

func TestGetDefaultInterface(t *testing.T) {
	iface := GetDefaultInterface()
	if iface == "" {
		t.Error("Expected a non-empty interface name, got empty string")
	}
	t.Logf("Detected default interface: %s", iface)
}

func TestIsWireless(t *testing.T) {
	testCases := []struct {
		name     string
		expected bool
	}{
		{"wlo1", true},
		{"wlan0", true},
		{"wlp2s0", true},
		{"wifi0", true},
		{"eth0", false},
		{"enp2s0", false},
		{"docker0", false},
		{"lo", false},
	}

	for _, tc := range testCases {
		res := isWireless(tc.name)
		if res != tc.expected {
			t.Errorf("isWireless(%q) = %v; expected %v", tc.name, res, tc.expected)
		}
	}
}

func TestFindInterfaceByIPWithLoopback(t *testing.T) {
	iface := findInterfaceByIP(net.ParseIP("127.0.0.1"))
	if iface != "" {
		t.Logf("Matched loopback: %s", iface)
	}
}
