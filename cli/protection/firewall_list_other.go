//go:build !windows && !linux

package protection

import (
	"context"
	"errors"
)

func (localFirewall) List(context.Context) ([]BlockEntry, error) {
	return nil, errors.New("listing Netwatch firewall blocks is not supported on this OS")
}
