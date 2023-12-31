//go:build !windows

package winsize

import (
	"syscall"
	"unsafe"
)

func GetWinsize() (ws WindowSize, err error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		err = errno
	}
	return ws, err
}
