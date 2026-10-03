//go:build windows

package protection

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func runFirewallCommand(ctx context.Context, name string, args []string) ([]byte, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	if name != "netsh" {
		return nil, errors.New("administrator approval is required for this firewall command")
	}
	// Only internally generated netsh arguments reach this branch. Validate them
	// again before embedding in a PowerShell command that requests UAC approval.
	for _, arg := range args {
		if arg == "" || strings.IndexFunc(arg, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '=')
		}) >= 0 {
			return nil, errors.New("unsafe firewall argument")
		}
	}
	command := strings.Join(args, " ")
	script := "$p = Start-Process -FilePath 'netsh.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList '" + command + "' -Wait -PassThru; if ($null -eq $p) { exit 1 }; exit $p.ExitCode"
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
