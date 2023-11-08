package util

import (
	"bytes"
	"fmt"
)

type UserNotFound struct {
	Username string
}

func (e UserNotFound) Error() string {
	return fmt.Sprintf("User not found: %s", e.Username)
}

type BytesReadCloser struct {
	*bytes.Reader
}

func (b *BytesReadCloser) Close() error { return nil }
