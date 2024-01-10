package ssh3

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

const MAJOR int = 0
const MINOR int = 1
const PATCH int = 5
const RC int = 5

type InvalidSSHVersion struct {
	versionString string
}

func (e InvalidSSHVersion) Error() string {
	return fmt.Sprintf("invalid ssh version string: %s", e.versionString)
}

type UnsupportedSSHVersion struct {
	versionString string
}

func (e UnsupportedSSHVersion) Error() string {
	return fmt.Sprintf("unsupported ssh version: %s", e.versionString)
}

// GetCurrentVersionString() returns the version string to be exchanged between two
// endpoints for version negotiation
func GetCurrentVersionString() string {
	return fmt.Sprintf("SSH 3.0 francoismichel/ssh3 %d.%d.%d", MAJOR, MINOR, PATCH)
}

func ParseVersionString(version string) (major int, minor int, patch int, err error) {
	fields := strings.Fields(version)
	if len(fields) < 4 || fields[0] != "SSH" || fields[1] != "3.0" {
		log.Error().Msgf("bad SSH version fields")
		return 0, 0, 0, InvalidSSHVersion{versionString: version}
	}
	majorDotMinor := strings.Split(fields[3], ".")
	if len(majorDotMinor) != 3 {
		log.Error().Msgf("bad SSH version major.minor.patch field")
		return 0, 0, 0, InvalidSSHVersion{versionString: version}
	}
	major, err = strconv.Atoi(majorDotMinor[0])
	if err != nil {
		log.Error().Msgf("bad SSH version major value")
		return 0, 0, 0, InvalidSSHVersion{versionString: version}
	}
	minor, err = strconv.Atoi(majorDotMinor[1])
	if err != nil {
		log.Error().Msgf("bad SSH version minor value")
		return 0, 0, 0, InvalidSSHVersion{versionString: version}
	}
	patch, err = strconv.Atoi(majorDotMinor[2])
	if err != nil {
		log.Error().Msgf("bad SSH version patch value")
		return 0, 0, 0, InvalidSSHVersion{versionString: version}
	}
	return major, minor, patch, nil
}

// GetCurrentSoftwareVersion() returns the current software version to be displayed to the user
// For version string to be communicated between endpoints, use GetCurrentVersionString() instead.
func GetCurrentSoftwareVersion() string {
	versionStr := fmt.Sprintf("%d.%d.%d", MAJOR, MINOR, PATCH)
	if RC > 0 {
		versionStr += fmt.Sprintf("-rc%d", RC)
	}
	return versionStr
}
