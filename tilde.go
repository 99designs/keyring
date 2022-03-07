package keyring

import (
	"os"
	"path/filepath"
	"strings"
)

// ~/ or ~\ depending on OS
var tildePrefix = string([]rune{'~', filepath.Separator})

// expand tilde for home directory
func ExpandTilde(dir string) (string, error) {
	if strings.HasPrefix(dir, tildePrefix) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = strings.Replace(dir, "~", homeDir, 1)
		debugf("Expanded file dir to %s", dir)
	}
	return dir, nil
}
