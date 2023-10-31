package util

import "bytes"


type BytesReadCloser struct {
	*bytes.Reader
}

func (b *BytesReadCloser) Close() error { return nil }