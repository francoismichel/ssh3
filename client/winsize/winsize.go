//go:build !windows

package winsize

import (
	"os"
	"syscall"
	"unsafe"
)

func GetWinsize(tty *os.File) (ws WindowSize, err error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tty.Fd()), uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		err = errno
	}
	return ws, err
}
