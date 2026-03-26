package unix_util

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
	"os"
	osuser "os/user"
	"strconv"
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

// getSupplementaryGroups returns the supplementary group IDs for the user.
// Used when running as root to set up a fully-privileged credential block.
func (u *User) getSupplementaryGroups() []uint32 {
  osUser, err := osuser.LookupId(strconv.FormatUint(u.Uid, 10))
  if err != nil {
    return nil
  }
  groupIds, err := osUser.GroupIds()
  if err != nil {
    return nil
  }
  groups := make([]uint32, 0, len(groupIds))
  for _, gidStr := range groupIds {
    gid, err := strconv.ParseUint(gidStr, 10, 32)
    if err != nil {
      continue
    }
    groups = append(groups, uint32(gid))
  }
  return groups
}

// buildCredential builds the syscall.Credential for exec'ing child processes.
//
// When running as root we supply the full set of supplementary groups so that
// the spawned shell inherits the correct group memberships.
//
// When running as a non-root user we set NoSetGroups=true to skip the
// setgroups(2) syscall, which always requires CAP_SETGID and therefore fails
// with EPERM for unprivileged processes.
func (u *User) buildCredential() *syscall.Credential {
  if os.Getuid() == 0 {
    return &syscall.Credential{
      Uid:    uint32(u.Uid),
      Gid:    uint32(u.Gid),
      Groups: u.getSupplementaryGroups(),
    }
  }
  return &syscall.Credential{
    Uid:         uint32(u.Uid),
    Gid:         uint32(u.Gid),
    NoSetGroups: true,
  }
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
	cmd.SysProcAttr.Credential = u.buildCredential()
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
	cmd.SysProcAttr.Credential = u.buildCredential()
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
