//go:build unix && (!linux || disable_password_auth)

package unix_util

import (
	"runtime"
	"strconv"

	"fmt"
	osuser "os/user"

	"github.com/rs/zerolog/log"
)

func getUser(username string) (*User, error) {
	u, err := osuser.Lookup(username)
	if err != nil {
		return nil, err
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 64)
	if err != nil {
		log.Error().Msgf("could not convert uid %s into a uint64", u.Uid)
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 64)
	if err != nil {
		log.Error().Msgf("could not convert gid %s into a uint64", u.Gid)
		return nil, err
	}

	return &User{
		Username: u.Username,
		Uid:      uid,
		Gid:      gid,
		Dir:      u.HomeDir,
		Shell:    "/bin/sh",
	}, nil
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func userPasswordAuthentication(username, password string) (bool, error) {
	return false, fmt.Errorf("password-based authentication is not implemented on %s/%s systems", runtime.GOOS, runtime.GOARCH)
}

func passwordAuthAvailable() bool {
	return false
}
