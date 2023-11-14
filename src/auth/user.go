package auth

/*
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
size_t size_of_passwd() { return sizeof(struct passwd); }
*/
import "C"
import (
	"io"
	"os/exec"
	"ssh3/src/util"
	"syscall"
	"unsafe"
)

type User struct {
	Username string
	Uid		 uint64
	Gid		 uint64
	Dir		 string
	Shell	 string
}

func GetUser(username string) (*User, error) {
	return getpwnam(username)
}

/*
 * Wrapper around ibc's getpwnam function
 */
 func getpwnam(name string) (*User, error) {
    cname := C.CString(name)
    defer C.free(unsafe.Pointer(cname))

    cpasswd := (*C.struct_passwd)(C.malloc(C.size_of_passwd()))
    defer C.free(unsafe.Pointer(cpasswd))

	bufLen := uint64(1024)
	cBufLen := C.sysconf(C._SC_GETPW_R_SIZE_MAX)
	if cBufLen > C.long(0) {
		bufLen = uint64(cBufLen)
	}


    buf := (*C.char)(C.malloc(C.ulong(bufLen)))
    defer C.free(unsafe.Pointer(buf))


    ret, err := C.getpwnam_r(cname, cpasswd, buf, C.ulong(bufLen), &cpasswd)

	if int(ret) != 0 {
		return nil, syscall.Errno(ret)
	}

    if unsafe.Pointer(cpasswd) == unsafe.Pointer(uintptr(0)) {
        if err == nil {
            err = util.UserNotFound{Username: name}
        }

        return nil, err
    }
    s := User {
        Username: C.GoString(cpasswd.pw_name),
        Uid: uint64(cpasswd.pw_uid),
        Gid: uint64(cpasswd.pw_gid),
		Dir: C.GoString(cpasswd.pw_dir),
		Shell: C.GoString(cpasswd.pw_shell),
    }

    return &s, nil
}


func (u *User) CreateShell(addEnv string, stdout, stderr io.Writer, stdin io.Reader) *exec.Cmd {
	return u.CreateCommand(addEnv, stdout, stderr, stdin, u.Shell)
}


func (u *User) CreateCommand(addEnv string, stdout, stderr io.Writer, stdin io.Reader, command string, args ...string) *exec.Cmd {
	cmd := exec.Command(command, args...)
	
	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(u.Uid), Gid: uint32(u.Gid)}

	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = stdin

	return cmd
}