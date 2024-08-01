package util

import (
	"bytes"
	"fmt"
)

// a JWT bearer token, encoded following the JWT specification
type JWTTokenString struct {
	Token string
}

type SSHForwardingProtocol = uint64
type SSHForwardingAddressFamily = uint64

type ChannelID = uint64

const (
	SSHProtocolUDP           = SSHForwardingProtocol(0)
	SSHForwardingProtocolTCP = SSHForwardingProtocol(1)
)

const (
	SSHAFIpv4 = SSHForwardingAddressFamily(4)
	SSHAFIpv6 = SSHForwardingAddressFamily(6)
)

type UserNotFound struct {
	Username string
}

func (e UserNotFound) Error() string {
	return fmt.Sprintf("User not found: %s", e.Username)
}

type ChannelNotFound struct {
	ChannelID ChannelID
}

func (e ChannelNotFound) Error() string {
	return fmt.Sprintf("Channel not found: %d", e.ChannelID)
}

type InvalidSSHString struct {
	Reason error
}

func (e InvalidSSHString) Error() string {
	return fmt.Sprintf("Invalid SSH string: %s", e.Reason)
}

type Unauthorized struct{}

func (e Unauthorized) Error() string {
	return "Unauthorized"
}

type OtherHTTPError struct {
	StatusCode int
	HasBody    bool
	Body       string
}

func (e OtherHTTPError) Error() string {
	str := fmt.Sprintf("HTTP response with %d status code", e.StatusCode)
	if e.HasBody {
		str = fmt.Sprintf("%s: %s", str, e.Body)
	}
	return str
}

type InvalidConfig struct {
	Field string
	Value string
}

func (e InvalidConfig) Error() string {
	return fmt.Sprintf("Invalid %s config field: \"%s\"", e.Field, e.Value)
}

type ClosedPluginsRegistry struct {

}

func (e ClosedPluginsRegistry) Error() string {
	return "The plugins registry is closed"
}

type BytesReadCloser struct {
	*bytes.Reader
}

func (b *BytesReadCloser) Close() error { return nil }

// sends an ssh3 datagram. The function must know the ID of the channel
type SSH3DatagramSenderFunc func(p []byte) error

type DatagramSender interface {
	SendDatagram(p []byte) error
}
