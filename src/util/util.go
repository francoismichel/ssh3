package util

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// copied and adapted from github.com/creack/pty
// StartWithAttrs assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
//
// This will resize the pty to the specified size before starting the command if a size is provided.
// The `attrs` parameter overrides the one set in c.SysProcAttr.
//
// This should generally not be needed. Used in some edge cases where it is needed to create a pty
// without a controlling terminal.
func StartWithAttrsAndPty(c *exec.Cmd, sz *ptylib.Winsize, attrs *syscall.SysProcAttr, pty *os.File, tty *os.File) error {
	defer func() { _ = tty.Close() }() // Best effort.

	if sz != nil {
		if err := ptylib.Setsize(pty, sz); err != nil {
			_ = pty.Close() // Best effort.
			return err
		}
	}
	if c.Stdout == nil {
		c.Stdout = tty
	}
	if c.Stderr == nil {
		c.Stderr = tty
	}
	if c.Stdin == nil {
		c.Stdin = tty
	}

	c.SysProcAttr = attrs

	if err := c.Start(); err != nil {
		_ = pty.Close() // Best effort.
		return err
	}
	return nil
}

// adapted from github.com/creack/pty
// StartWithSize assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
//
// This will resize the pty to the specified size before starting the command.
// Starts the process in a new session and sets the controlling terminal.
func StartWithSizeAndPty(cmd *exec.Cmd, ws *ptylib.Winsize, pty *os.File, tty *os.File) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	return StartWithAttrsAndPty(cmd, ws, cmd.SysProcAttr, pty, tty)
}


// copied from "net/http/internal/ascii"
// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func ConfigureLogger(logLevel string) {
	switch strings.ToLower(logLevel) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}
}


// Accept queue copied from https://github.com/quic-go/webtransport-go/blob/master/session.go
type AcceptQueue[T any] struct {
	mx sync.Mutex
	// The channel is used to notify consumers (via Chan) about new incoming items.
	// Needs to be buffered to preserve the notification if an item is enqueued
	// between a call to Next and to Chan.
	c chan struct{}
	// Contains all the streams waiting to be accepted.
	// There's no explicit limit to the length of the queue, but it is implicitly
	// limited by the stream flow control provided by QUIC.
	queue []T
}

func NewAcceptQueue[T any]() *AcceptQueue[T] {
	return &AcceptQueue[T]{c: make(chan struct{}, 1)}
}

func (q *AcceptQueue[T]) Add(str T) {
	q.mx.Lock()
	q.queue = append(q.queue, str)
	q.mx.Unlock()

	select {
	case q.c <- struct{}{}:
	default:
	}
}

func (q *AcceptQueue[T]) Next() T {
	q.mx.Lock()
	defer q.mx.Unlock()

	if len(q.queue) == 0 {
		return *new(T)
	}
	str := q.queue[0]
	q.queue = q.queue[1:]
	return str
}

func (q *AcceptQueue[T]) Chan() <-chan struct{} { return q.c }


type DatagramsQueue struct {
	c chan []byte
}

func NewDatagramsQueue(len uint64) *DatagramsQueue {
	return &DatagramsQueue{c: make(chan []byte, len)}
}

// returns true if added, false otherwise
func (q *DatagramsQueue) Add(datagram []byte) bool {
	select {
	case q.c <- datagram:
		return true
	default:
		return false
	}
}

// returns nil if added, the context closing error (context.Cause(ctx)) otherwise
func (q *DatagramsQueue) WaitAdd(ctx context.Context, datagram []byte) error {
	select {
	case q.c <- datagram:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}


func (q *DatagramsQueue) Next() []byte {
	select {
	case datagram := <-q.c:
		return datagram
	default:
		return nil
	}
}

func (q *DatagramsQueue) WaitNext(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-q.c:
		return datagram, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

type AgentSigningMethod struct {
	Agent agent.ExtendedAgent
	Key *agent.Key
}

func (m *AgentSigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	panic("not implemented")
}

func (m *AgentSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	pk, ok := key.(ssh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bad key type: %T instead of ssh.PublicKey", pk)
	}
	before := time.Now()
	signature, err := m.Agent.SignWithFlags(pk, []byte(signingString), agent.SignatureFlagRsaSha256)
	if err != nil {
		return nil, err
	}
	log.Error().Msgf("elapsed: %+v", time.Since(before))
	return signature.Blob, nil
}

func (m *AgentSigningMethod) Alg() string {
	switch m.Key.Type() {
	case "ssh-rsa":
		return "RS256"
	case "ssh-ed25519":
		return "EdDSA"
	}
	return ""
}
