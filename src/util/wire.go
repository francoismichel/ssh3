// copied from github.com/quic-go/quic-go

package util

import (
	"bytes"
	"fmt"
	"io"
)

// taken from the QUIC draft
const (
	// Min is the minimum value allowed for a QUIC varint.
	Min = 0

	// Max is the maximum allowed value for a QUIC varint (2^62-1).
	Max = maxVarInt8

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// Reader implements both the io.ByteReader and io.Reader interfaces.
type Reader interface {
	io.ByteReader
	io.ReadCloser
}

type byteReader struct {
	io.ReadCloser
}

var _ Reader = &byteReader{}

// NewReader returns a Reader for r.
// If r already implements both io.ByteReader and io.Reader, NewReader returns r.
// Otherwise, r is wrapped to add the missing interfaces.
func NewReader(r io.ReadCloser) Reader {
	if r, ok := r.(Reader); ok {
		return r
	}
	return &byteReader{r}
}

func (r *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := r.ReadCloser.Read(b[:])
	if n == 1 && err == io.EOF {
		err = nil
	}
	return b[0], err
}

// Writer implements both the io.ByteWriter and io.Writer interfaces.
type Writer interface {
	io.ByteWriter
	io.Writer
}

var _ Writer = &bytes.Buffer{}

type byteWriter struct {
	io.Writer
}

var _ Writer = &byteWriter{}

// NewWriter returns a Writer for w.
// If r already implements both io.ByteWriter and io.Writer, NewWriter returns w.
// Otherwise, w is wrapped to add the missing interfaces.
func NewWriter(w io.Writer) Writer {
	if w, ok := w.(Writer); ok {
		return w
	}
	return &byteWriter{w}
}

func (w *byteWriter) WriteByte(c byte) error {
	_, err := w.Writer.Write([]byte{c})
	return err
}

// ReadVarInt reads a number in the QUIC varint format from r.
func ReadVarInt(r Reader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

// AppendVarInt appends i in the QUIC varint format.
func AppendVarInt(b []byte, i uint64) []byte {
	if i <= maxVarInt1 {
		return append(b, uint8(i))
	}
	if i <= maxVarInt2 {
		return append(b, []byte{uint8(i>>8) | 0x40, uint8(i)}...)
	}
	if i <= maxVarInt4 {
		return append(b, []byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)}...)
	}
	if i <= maxVarInt8 {
		return append(b, []byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		}...)
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}

// AppendVarIntWithLen append i in the QUIC varint format with the desired length.
func AppendVarIntWithLen(b []byte, i uint64, length uint64) []byte {
	if length != 1 && length != 2 && length != 4 && length != 8 {
		panic("invalid varint length")
	}
	l := VarIntLen(i)
	if l == length {
		return AppendVarInt(b, i)
	}
	if l > length {
		panic(fmt.Sprintf("cannot encode %d in %d bytes", i, length))
	}
	if length == 2 {
		b = append(b, 0b01000000)
	} else if length == 4 {
		b = append(b, 0b10000000)
	} else if length == 8 {
		b = append(b, 0b11000000)
	}
	for j := uint64(1); j < length-l; j++ {
		b = append(b, 0)
	}
	for j := uint64(0); j < l; j++ {
		b = append(b, uint8(i>>(8*(l-1-j))))
	}
	return b
}

// VarIntLen determines the number of bytes that will be needed to write the number i.
func VarIntLen(i uint64) uint64 {
	if i <= maxVarInt1 {
		return 1
	}
	if i <= maxVarInt2 {
		return 2
	}
	if i <= maxVarInt4 {
		return 4
	}
	if i <= maxVarInt8 {
		return 8
	}
	// Don't use a fmt.Sprintf here to format the error message.
	// The function would then exceed the inlining budget.
	panic(struct {
		message string
		num     uint64
	}{"value doesn't fit into 62 bits: ", i})
}

func ParseSSHString(buf Reader) (string, error) {
	length, err := ReadVarInt(buf)
	if err != nil {
		return "", err
	}
	out := make([]byte, length)
	_, err = io.ReadFull(buf, out)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func WriteSSHString(out []byte, s string) (int, error) {
	if uint64(len(out)) < uint64(SSHStringLen(s)) {
		return 0, fmt.Errorf("buffer too small to write varint: %d < %d", len(out), SSHStringLen(s))
	}
	buf := AppendVarInt(nil, uint64(len(s)))

	copied := copy(out, buf)
	copied += copy(out[copied:], s)
	return copied, nil
}

func SSHStringLen(s string) int {
	return int(VarIntLen(uint64(len(s)))) + len(s)
}

func MinUint64(a uint64, b uint64) uint64 {
	if a <= b {
		return a
	}
	return b
}