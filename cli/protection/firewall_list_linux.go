//go:build linux

package protection

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (localFirewall) List(ctx context.Context) ([]BlockEntry, error) {
	listing.Lock()
	defer listing.Unlock()
	if time.Since(listing.read) >= listingLifetime {
		output, err := asRoot(ctx, "iptables", []string{"-S", "INPUT"})
		if err != nil {
			return nil, fmt.Errorf("could not inspect Linux firewall rules: %w", err)
		}
		listing.blocks, listing.read = parseBlocks(string(output)), time.Now()
	}
	return append([]BlockEntry(nil), listing.blocks...), nil
}

// parseBlocks reads `iptables -S INPUT` and keeps the DROP rules Netwatch named.
func parseBlocks(output string) []BlockEntry {
	var blocks []BlockEntry
	for _, line := range strings.Split(output, "\n") {
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
	return blocks
}
