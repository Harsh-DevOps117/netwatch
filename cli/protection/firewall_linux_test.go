//go:build linux

package protection

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Stand-ins for the system tools, so the approval path is tested without touching the firewall.
func fakeTools(t *testing.T, sudo, pkexec string) {
	dir := t.TempDir()
	for name, body := range map[string]string{"iptables": "echo rules \"$@\"", "sudo": sudo, "pkexec": pkexec} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

func TestLinuxFirewallAsksForApprovalWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root needs no approval")
	}
	const refused, approved = "echo 'sudo: a password is required' >&2; exit 1", "shift; exec /bin/sh \"$@\""
	run := func() (string, error) {
		output, err := asRoot(context.Background(), "iptables", []string{"-S", "INPUT"})
		return strings.TrimSpace(string(output)), err
	}
	fakeTools(t, "shift; exec /bin/sh \"$@\"", "exit 99")
	if output, err := run(); err != nil || output != "rules -S INPUT" {
		t.Fatalf("passwordless sudo is used without a prompt: %q %v", output, err)
	}
	fakeTools(t, refused, approved)
	if output, err := run(); err != nil || output != "rules -S INPUT" {
		t.Fatalf("the desktop prompt is the fallback when sudo wants a password: %q %v", output, err)
	}
	fakeTools(t, refused, "exit 126")
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("a dismissed prompt must read as declined: %v", err)
	}
	fakeTools(t, refused, "exit 127")
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "sudo without a password") {
		t.Fatalf("no prompt available must say what to set up: %v", err)
	}
	// The firewall's own failure under sudo is its answer, not a reason to prompt.
	fakeTools(t, "echo 'iptables: Bad rule' >&2; exit 1", approved)
	if output, err := run(); err == nil || output != "iptables: Bad rule" {
		t.Fatalf("a firewall error under sudo must be returned as it is: %q %v", output, err)
	}
}

func TestLinuxListingFollowsNetwatchChanges(t *testing.T) {
	const first, second = "Netwatch-0123456789abcdef0123456789abcdef", "Netwatch-fedcba9876543210fedcba9876543210"
	blocks := parseBlocks("-P INPUT ACCEPT\n" +
		"-A INPUT -s 10.20.0.9/32 -m comment --comment " + first + " -j DROP\n" +
		"-A INPUT -s 10.20.0.10/32 -m comment --comment \"someone else\" -j DROP\n" +
		"-A INPUT -s 10.20.0.11/32 -m comment --comment " + second + " -j ACCEPT\n")
	if want := []BlockEntry{{SourceIP: "10.20.0.9", Rule: first}}; !reflect.DeepEqual(blocks, want) {
		t.Fatalf("only Netwatch-named DROP rules are blocks: %+v", blocks)
	}
	rule := func(op, ip, name string) []string {
		return []string{op, "INPUT", "-s", ip, "-m", "comment", "--comment", name, "-j", "DROP"}
	}
	listing.blocks, listing.read = blocks, time.Now()
	noteChange(rule("-I", "10.20.0.7", second))
	noteChange(rule("-D", "10.20.0.9", first))
	if want := []BlockEntry{{SourceIP: "10.20.0.7", Rule: second}}; !reflect.DeepEqual(listing.blocks, want) {
		t.Fatalf("a fresh reading follows Netwatch's own changes: %+v", listing.blocks)
	}
	// An expired reading is not patched: the next list must read the firewall again.
	listing.read = time.Now().Add(-listingLifetime)
	noteChange(rule("-I", "10.20.0.8", first))
	if len(listing.blocks) != 1 {
		t.Fatalf("an expired reading was changed: %+v", listing.blocks)
	}
	listing.blocks, listing.read = nil, time.Time{}
}
