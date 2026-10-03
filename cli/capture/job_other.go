//go:build !windows

package capture

import "os/exec"

func bindCaptureLifetime(_ *exec.Cmd) (func(), error) {
	return func() {}, nil
}
