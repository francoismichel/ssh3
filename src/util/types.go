package util

import "bytes"

type UserNotFound struct {
	Username string
}

type BytesReadCloser struct {
	*bytes.Reader
}

func (b *BytesReadCloser) Close() error { return nil }
