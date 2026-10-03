//go:build linux

package protection

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func (localFirewall) List(ctx context.Context) ([]BlockEntry, error) {
	output, err := exec.CommandContext(ctx, "iptables", "-S", "INPUT").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("could not inspect Linux firewall rules: %w", err)
	}
	var blocks []BlockEntry
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(strings.ReplaceAll(line, `"`, ""))
		if len(fields) < 10 || fields[0] != "-A" || fields[1] != "INPUT" {
			continue
		}
		var ip, rule, target string
		for i := 2; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-s":
				ip = strings.TrimSuffix(fields[i+1], "/32")
			case "--comment":
				rule = fields[i+1]
			case "-j":
				target = fields[i+1]
			}
		}
		if target == "DROP" && managedRuleName.MatchString(rule) && blockableIPv4(ip) {
			blocks = append(blocks, BlockEntry{SourceIP: ip, Rule: rule})
		}
	}
	return blocks, nil
}
