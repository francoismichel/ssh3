//go:build unix

package unix_util

import (
	"strconv"

	"github.com/rs/zerolog/log"
	"fmt"
	osuser "os/user"
)


func getUser(username string) (*User, error) {
	u, err := osuser.Lookup(username)
	if err != nil {
		return nil, err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		log.Error().Msgf("could not convert uid %s into an int")
		return nil, err
	}
	gid, err := strconv.Atoi(u.Uid)
	if err != nil {
		log.Error().Msgf("could not convert gid %s into an int")
		return nil, err
	}

	return &User{
		Username: u.Username,
		Uid: uint64(uid),
		Gid: uint64(gid),
		Dir: u.HomeDir,
		Shell: "/bin/sh",
	}, nil
}


/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
 func userPasswordAuthentication(username, password string) (bool, error) {
	return false,  fmt.Errorf("password-based authentication is not implemented on non-Linux Unix platforms")
}