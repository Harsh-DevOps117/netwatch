//go:build linux

package protection

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"
)

// One reading of the firewall serves the calls that follow an operator's click
// (the check before an unblock, the dashboard's refresh after a change), so one
// action asks for administrator approval once.
const listingLifetime = 2 * time.Minute

var listing struct {
	sync.Mutex
	blocks []BlockEntry
	read   time.Time
}

func runFirewallCommand(ctx context.Context, name string, args []string) ([]byte, error) {
	output, err := asRoot(ctx, name, args)
	if err == nil {
		noteChange(args)
	}
	return output, err
}

// asRoot runs one firewall command with root rights. Netwatch runs as the
// operator, and iptables needs root even to read its rules. The command runs
// directly when Netwatch is root, else through sudo when sudo needs no
// password, else through pkexec, the desktop's administrator prompt. Nothing
// here asks on the terminal: the dashboard shares it with the interactive CLI.
func asRoot(ctx context.Context, name string, args []string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 {
		return exec.CommandContext(ctx, path, args...).CombinedOutput()
	}
	if sudo, err := exec.LookPath("sudo"); err == nil {
		output, err := exec.CommandContext(ctx, sudo, append([]string{"-n", path}, args...)...).CombinedOutput()
		// sudo's own refusal starts with "sudo:"; anything else is the firewall's answer.
		if err == nil || !bytes.HasPrefix(bytes.TrimSpace(output), []byte("sudo:")) {
			return output, err
		}
	}
	const noPrompt = "the firewall needs root on Linux and no administrator prompt is available; allow this user to run iptables through sudo without a password"
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return nil, errors.New(noPrompt)
	}
	output, err := exec.CommandContext(ctx, pkexec, append([]string{"--disable-internal-agent", path}, args...)...).CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		switch exit.ExitCode() {
		case 126:
			return output, errors.New("administrator approval was declined")
		case 127:
			return output, errors.New(noPrompt)
		}
	}
	return output, err
}

// noteChange keeps a fresh reading in step with a rule Netwatch just added or
// removed. A reading that has expired, or was never taken, is left alone.
func noteChange(args []string) {
	var ip, rule string
	for i := 1; i+1 < len(args); i++ {
		switch args[i] {
		case "-s":
			ip = args[i+1]
		case "--comment":
			rule = args[i+1]
		}
	}
	listing.Lock()
	defer listing.Unlock()
	if ip == "" || rule == "" || time.Since(listing.read) >= listingLifetime {
		return
	}
	kept := make([]BlockEntry, 0, len(listing.blocks)+1)
	if args[0] == "-I" {
		kept = append(kept, BlockEntry{SourceIP: ip, Rule: rule})
	}
	for _, block := range listing.blocks {
		if block.SourceIP != ip || block.Rule != rule {
			kept = append(kept, block)
		}
	}
	listing.blocks = kept
}
