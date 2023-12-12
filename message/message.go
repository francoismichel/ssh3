package ssh3

import (
	"errors"
	"io"
	"ssh3/util"
)

// ssh messages type
const SSH_MSG_DISCONNECT                  =     1
const SSH_MSG_IGNORE                      =     2
const SSH_MSG_UNIMPLEMENTED               =     3
const SSH_MSG_DEBUG                       =     4
const SSH_MSG_SERVICE_REQUEST             =     5
const SSH_MSG_SERVICE_ACCEPT              =     6
const SSH_MSG_KEXINIT                     =    20
const SSH_MSG_NEWKEYS                     =    21
const SSH_MSG_USERAUTH_REQUEST            =    50
const SSH_MSG_USERAUTH_FAILURE            =    51
const SSH_MSG_USERAUTH_SUCCESS            =    52
const SSH_MSG_USERAUTH_BANNER             =    53
const SSH_MSG_GLOBAL_REQUEST              =    80
const SSH_MSG_REQUEST_SUCCESS             =    81
const SSH_MSG_REQUEST_FAILURE             =    82
const SSH_MSG_CHANNEL_OPEN                =    90
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION   =    91
const SSH_MSG_CHANNEL_OPEN_FAILURE        =    92
const SSH_MSG_CHANNEL_WINDOW_ADJUST       =    93
const SSH_MSG_CHANNEL_DATA                =    94
const SSH_MSG_CHANNEL_EXTENDED_DATA       =    95
const SSH_MSG_CHANNEL_EOF                 =    96
const SSH_MSG_CHANNEL_CLOSE               =    97
const SSH_MSG_CHANNEL_REQUEST             =    98
const SSH_MSG_CHANNEL_SUCCESS             =    99
const SSH_MSG_CHANNEL_FAILURE             =   100

type SSHDataType uint64
const (
	SSH_EXTENDED_DATA_NONE SSHDataType = 0
    SSH_EXTENDED_DATA_STDERR SSHDataType = 1
)

type Message interface {
	Write(buf []byte) (n int, err error)
	Length() int
}

type ChannelOpenConfirmationMessage struct {
	MaxPacketSize uint64
}

var _ Message = &ChannelOpenConfirmationMessage{}

func ParseChannelOpenConfirmationMessage(buf util.Reader) (*ChannelOpenConfirmationMessage, error) {
	maxPacketSize, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	return &ChannelOpenConfirmationMessage{
		MaxPacketSize: maxPacketSize,
	}, nil
}

func (m *ChannelOpenConfirmationMessage) Write(buf []byte) (consumed int, err error) {
	varintBuf := util.AppendVarInt(nil, uint64(SSH_MSG_CHANNEL_OPEN_CONFIRMATION))
	varintBuf = util.AppendVarInt(varintBuf, m.MaxPacketSize)
	consumed = copy(buf, varintBuf)
	return consumed, nil
}

func (m *ChannelOpenConfirmationMessage) Length() int {
	messageTypeLen := util.VarIntLen(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
	maxPacketSizeLen := util.VarIntLen(m.MaxPacketSize)
	return int(messageTypeLen) + int(maxPacketSizeLen)
}


type ChannelOpenFailureMessage struct {
	ReasonCode			 uint64
	ErrorMessageUTF8     string
	LanguageTag          string
}

var _ Message = &ChannelOpenFailureMessage{}

func ParseChannelOpenFailureMessage(buf util.Reader) (*ChannelOpenFailureMessage, error) {
	reasonCode, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	errorMessageUTF8, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}

	languageTag, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	return &ChannelOpenFailureMessage{
		ReasonCode:		  reasonCode,
		ErrorMessageUTF8:     errorMessageUTF8,
		LanguageTag:          languageTag,
	}, nil
}

func (m *ChannelOpenFailureMessage) Length() int {
	messageTypeLen := util.VarIntLen(SSH_MSG_CHANNEL_OPEN_FAILURE)
	reasonCodeLen := util.VarIntLen(m.ReasonCode)
	return int(messageTypeLen) + int(reasonCodeLen) + util.SSHStringLen(m.ErrorMessageUTF8) + util.SSHStringLen(m.LanguageTag)
}

func (m *ChannelOpenFailureMessage) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, errors.New("buffer too small to write channel open failure message")
	}

	varintBuf := util.AppendVarInt(nil, uint64(SSH_MSG_CHANNEL_OPEN_FAILURE))
	varintBuf = util.AppendVarInt(varintBuf, uint64(m.ReasonCode))
	consumed += copy(buf[consumed:], varintBuf)

	n, err := util.WriteSSHString(buf[consumed:], m.ErrorMessageUTF8)
	if err != nil {
		return 0, err
	}
	consumed += n

	n, err = util.WriteSSHString(buf[consumed:], m.LanguageTag)
	if err != nil {
		return 0, err
	}
	consumed += n

	return consumed, nil
}


type DataOrExtendedDataMessage struct {
	DataType SSHDataType
	Data string
}

var _ Message = &DataOrExtendedDataMessage{}

func ParseDataMessage(buf util.Reader) (*DataOrExtendedDataMessage, error) {
	data, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &DataOrExtendedDataMessage{
		DataType: SSH_EXTENDED_DATA_NONE,
		Data: data,
	}, nil
}

func (m *DataOrExtendedDataMessage) Write(buf []byte) (consumed int, err error) {
	if m.DataType == SSH_EXTENDED_DATA_NONE {
		msgTypeBuf := util.AppendVarInt(nil, uint64(SSH_MSG_CHANNEL_DATA))
		consumed += copy(buf[consumed:], msgTypeBuf)
	} else {
		msgTypeBuf := util.AppendVarInt(nil, uint64(SSH_MSG_CHANNEL_EXTENDED_DATA))
		consumed += copy(buf[consumed:], msgTypeBuf)
		dataTypeBuf := util.AppendVarInt(nil, uint64(m.DataType))
		consumed += copy(buf[consumed:], dataTypeBuf)
	}
	n, err := util.WriteSSHString(buf[consumed:], m.Data)
	if err != nil {
		return 0, err
	}
	consumed += n
	return consumed, nil
}

func (m *DataOrExtendedDataMessage) Length() int {
	if m.DataType == SSH_EXTENDED_DATA_NONE {
		messageTypeLen := util.VarIntLen(SSH_MSG_CHANNEL_DATA)
		return int(messageTypeLen) + int(util.SSHStringLen(m.Data))
	}
	messageTypeLen := util.VarIntLen(SSH_MSG_CHANNEL_EXTENDED_DATA)
	return int(messageTypeLen) + int(util.VarIntLen(uint64(m.DataType))) + int(util.SSHStringLen(m.Data))
}

func ParseExtendedDataMessage(buf util.Reader) (*DataOrExtendedDataMessage, error) {
	dataType, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	data, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &DataOrExtendedDataMessage{
		DataType: SSHDataType(dataType),
		Data: data,
	}, err
}

func ParseMessage(r util.Reader) (Message, error) {
	typeId, err := util.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	switch typeId {
		case SSH_MSG_CHANNEL_REQUEST:
			return ParseRequestMessage(r)
		case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
			return ParseChannelOpenConfirmationMessage(r)
		case SSH_MSG_CHANNEL_OPEN_FAILURE:
			return ParseChannelOpenFailureMessage(r)
		case SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA:
			if typeId == SSH_MSG_CHANNEL_DATA {
				return ParseDataMessage(r)
			} else {
				return ParseExtendedDataMessage(r)
			}
		default:
			panic("not implemented")
	}
}