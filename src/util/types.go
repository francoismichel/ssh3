package util

import (
	"bytes"
	"fmt"
)

type SSHForwardingProtocol = uint64
type SSHForwardingAddressFamily = uint64

type ConversationID = uint64
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

type BytesReadCloser struct {
	*bytes.Reader
}

func (b *BytesReadCloser) Close() error { return nil }

// sends an ssh3 datagram. The function must know the ID of the channel
type SSH3DatagramSenderFunc func(p []byte) error

type MessageSender interface {
	SendMessage(p []byte) error
}
