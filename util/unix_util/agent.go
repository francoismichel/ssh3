package unix_util

import (
	"fmt"
	"os"
	"path"
)

func NewUnixSocketPath() (string, error) {
	dir, err := os.MkdirTemp("/tmp/", "")
	if err != nil {
		return "", err
	}
	return path.Join(dir, fmt.Sprintf("agent.%d", os.Getpid())), nil
}
