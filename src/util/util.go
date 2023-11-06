package util

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	ptylib "github.com/creack/pty"
	"github.com/rs/zerolog"
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