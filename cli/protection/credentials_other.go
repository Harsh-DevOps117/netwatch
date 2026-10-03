//go:build !windows

package protection

func sealKey(input []byte) ([]byte, error) { return append([]byte(nil), input...), nil }
func openKey(input []byte) ([]byte, error) { return append([]byte(nil), input...), nil }
