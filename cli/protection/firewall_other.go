//go:build !windows

package protection

import (
	"context"
	"os/exec"
)

func runFirewallCommand(ctx context.Context, name string, args []string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
