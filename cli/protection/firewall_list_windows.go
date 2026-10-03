//go:build windows

package protection

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func (localFirewall) List(ctx context.Context) ([]BlockEntry, error) {
	// This is a fixed read-only query. Never interpolate client input into it.
	const script = `$ErrorActionPreference='Stop'; Get-NetFirewallRule -DisplayName 'Netwatch-*' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' -and $_.Enabled -eq 'True' } | ForEach-Object { $rule=$_; $filter=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule; foreach($ip in @($filter.RemoteAddress)) { [Console]::WriteLine($rule.DisplayName + [char]9 + $ip) } }`
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("could not inspect Windows firewall rules: %w", err)
	}
	var blocks []BlockEntry
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		rule, ip := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if managedRuleName.MatchString(rule) && blockableIPv4(ip) {
			blocks = append(blocks, BlockEntry{SourceIP: ip, Rule: rule})
		}
	}
	return blocks, nil
}
