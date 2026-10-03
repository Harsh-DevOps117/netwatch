package protection

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func credentialPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "", errors.New("user config directory is unavailable")
	}
	return filepath.Join(dir, "netwatch", "groq-api-key"), nil
}

func validAPIKey(key string) bool {
	return key != "" && key == strings.TrimSpace(key) && len(key) <= 512 && !strings.ContainsAny(key, "\r\n")
}

// SaveAPIKey stores a per-user key outside the repository. Windows encrypts it
// with the current user's DPAPI profile; other systems use a mode-0600 file.
func SaveAPIKey(key string) error {
	if !validAPIKey(key) {
		return errors.New("enter a valid Groq API key")
	}
	path, err := credentialPath()
	if err != nil {
		return err
	}
	sealed, err := sealKey([]byte(key))
	if err != nil {
		return fmt.Errorf("could not protect Groq API key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".groq-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func LoadAPIKey() (string, error) {
	path, err := credentialPath()
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return "", errors.New("Groq key file has unsafe permissions or type")
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key, err := openKey(sealed)
	if err != nil {
		return "", fmt.Errorf("could not open saved Groq API key: %w", err)
	}
	if !validAPIKey(string(key)) {
		return "", errors.New("saved Groq API key is invalid")
	}
	return string(key), nil
}

func ClearAPIKey() error {
	path, err := credentialPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
