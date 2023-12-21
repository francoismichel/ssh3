package unix_util

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
)

type User struct {
	Username string
	Uid      uint64
	Gid      uint64
	Dir      string
	Shell    string
}

func GetUser(username string) (*User, error) {
	return getUser(username)
}

func (u *User) CreateCommand(addEnv string, stdout, stderr io.Writer, stdin io.Reader, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	if loginShell {
		// from man bash: A  login shell is one whose first character of argument zero is a -, or
		// 				  one started with the --login option.
		// We chose to start it with a preprended "-"
		cmd.Args[0] = fmt.Sprintf("-%s", filepath.Base(cmd.Args[0]))
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(u.Uid), Gid: uint32(u.Gid)}

	var err error
	var stdoutR, stderrR io.Reader
	var stdinW io.Writer

	if stdout == nil {
		stdoutR, err = cmd.StdoutPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdout = stdout
	}
	if stderr == nil {
		stderrR, err = cmd.StderrPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stderr = stderr
	}
	if stdin == nil {
		stdinW, err = cmd.StdinPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdin = stdin
	}

	return cmd, stdoutR, stderrR, stdinW, err
}

func (u *User) CreateCommandPipeOutput(addEnv string, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, error) {
	cmd := exec.Command(command, args...)

	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(u.Uid), Gid: uint32(u.Gid)}

	return u.CreateCommand(addEnv, nil, nil, nil, loginShell, command, args...)
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func UserPasswordAuthentication(username, password string) (bool, error) {
	return userPasswordAuthentication(username, password)
}

func PasswordAuthAvailable() bool {
	return passwordAuthAvailable()
}
