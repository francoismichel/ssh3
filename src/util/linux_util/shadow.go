//  Copyright 2018 Google LLC
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at

//        https://www.apache.org/licenses/LICENSE-2.0

//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//	limitations under the License.

/*
Package passwd implements a minion that looks for simple issues within
/etc/passwd and /etc/shadow files.

It contains functions that allow one to check if users can login without
passwords, use weak hashes or are not root, but their uid is 0.

It also checks whether those files have insecure UNIX permissions.
*/

// partially copied from https://github.com/google/minions/blob/v0.1.0/src/go/minions/passwd/minion.go

package linux_util

/*
#cgo LDFLAGS: -lcrypt
#include <stdlib.h>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>
size_t size_of_shadow() { return sizeof(struct spwd); }
size_t size_of_crypt_data() { return sizeof(struct crypt_data); }
int get_errno() { return errno; }
*/
import "C"
import (
	"fmt"
	"ssh3/src/auth"
	"ssh3/src/util"
	"syscall"
	"unsafe"
)

type ShadowEntry struct {
	Username string
	Password string
}


/*
 * Wrapper around libshadow's getspnam function
 * copied from https://stackoverflow.com/questions/38790092/call-a-c-function-from-go
 */
func Getspnam(name string) (*ShadowEntry, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	cspwd := (*C.struct_spwd)(C.malloc(C.size_of_shadow()))
	defer C.free(unsafe.Pointer(cspwd))

	buf := (*C.char)(C.malloc(1024))
	defer C.free(unsafe.Pointer(buf))

	_, err := C.getspnam_r(cname, cspwd, buf, 1024, &cspwd)

	if unsafe.Pointer(cspwd) == unsafe.Pointer(uintptr(0)) {
		if err == nil {
			err = util.UserNotFound{Username: name}
		}

		return nil, err
	}

	s := ShadowEntry{
		Username: C.GoString(cspwd.sp_namp),
		Password: C.GoString(cspwd.sp_pwdp),
	}

	return &s, nil
}

/*
 * Wrapper around libc's crypt function
 * Similarly to the original function, the setting string
 * can also be a fully hashed password, crypt() will only
 * look at the three first components.
 */
func Crypt(clearPassword, setting string) (string, error) {
	cPassword := C.CString(clearPassword)
	defer C.free(unsafe.Pointer(cPassword))

	cSetting := C.CString(string(setting))
	defer C.free(unsafe.Pointer(cSetting))

	ccrypt_data := (*C.struct_crypt_data)(C.malloc(C.size_of_crypt_data()))
	defer C.free(unsafe.Pointer(ccrypt_data))

	C.crypt_r(cPassword, cSetting, ccrypt_data)

	hashedPassword := C.GoString(&ccrypt_data.output[0])
	if hashedPassword[0] == '*' {
		return "", fmt.Errorf("bad password hashing")
	}
	return hashedPassword, nil
}

func SetEUid(uid int32) error {
	ret := C.seteuid(C.__uid_t(uid))
	if ret != 0 {
		return syscall.Errno(C.get_errno())
	}
	return nil
}

func SetEGid(gid int32) error {
	ret := C.setegid(C.__uid_t(gid))
	if ret != 0 {
		return syscall.Errno(C.get_errno())
	}
	return nil
}

func GetEUid() int32 {
	return int32(C.geteuid())
}

func GetUid() int32 {
	return int32(C.getuid())
}

func GetEGid() int32 {
	return int32(C.geteuid())
}

func GetGid() int32 {
	return int32(C.getgid())
}

func TemporarilySetUserIDs(user *auth.User) error {
	err := SetEUid((int32(user.Uid)))
	if err != nil {
		return err
	}
	err = SetEGid(int32(user.Gid))
	if err != nil {
		return err
	}
	return nil
}

func RestoreUserIDs() error {
	err := SetEUid(GetUid())
	if err != nil {
		return err
	}
	err = SetEGid(GetGid())
	if err != nil {
		return err
	}
	return nil
}

/*
 * Compares the provided password with the one stored in the shadow passwords table (generally /etc/shadow)
 */
func ComparePasswordWithHashedPassword(candidatePassword string, hashedPassword string) (bool, error) {
	candidateHashedPassword, err := Crypt(candidatePassword, string(hashedPassword))
	return candidateHashedPassword == string(hashedPassword), err
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func UserPasswordAuthentication(username, password string) (bool, error) {
	shadowEntry, err := Getspnam(username)
	if err != nil {
		return false, nil
	}
	return ComparePasswordWithHashedPassword(password, shadowEntry.Password)
}
