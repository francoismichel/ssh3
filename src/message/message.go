package ssh3

import (
	"ssh3/src/util"
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

type DataOrExtendedDataMessage struct {
	DataType SSHDataType
	Data string
}

var _ Message = &DataOrExtendedDataMessage{}

func ParseDataMessage(buf util.Reader) (*DataOrExtendedDataMessage, error) {
	data, err := util.ParseSSHString(buf)
	if err != nil {
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
	if err != nil {
		return nil, err
	}
	return &DataOrExtendedDataMessage{
		DataType: SSHDataType(dataType),
		Data: data,
	}, nil
}

func ParseMessage(r util.Reader) (Message, error) {
	typeId, err := util.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	switch typeId {
		case SSH_MSG_CHANNEL_REQUEST:
			requestMessage, err := ParseRequestMessage(r)
			if err != nil {
				return nil, err
			}
			return requestMessage, nil
		case SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA:
			var dataMessage *DataOrExtendedDataMessage
			var err error
			if typeId == SSH_MSG_CHANNEL_DATA {
				dataMessage, err = ParseDataMessage(r)
			} else {
				dataMessage, err = ParseExtendedDataMessage(r)
			}
			if err != nil {
				return nil, err
			}
			return dataMessage, nil

		default:
			panic("not implemented")
	}
}