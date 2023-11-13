package ssh3

import (
	"sync"

	"github.com/quic-go/quic-go/http3"
	"ssh3/src/util"
)


type conversationsManager struct {
	connection http3.StreamCreator
	conversations map[util.ConversationID]*Conversation
	lock sync.Mutex
}

func newConversationManager(connection http3.StreamCreator) *conversationsManager {
	return &conversationsManager{ connection: connection, conversations: make(map[util.ConversationID]*Conversation)}
}

func (m *conversationsManager) addConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.conversations[util.ConversationID(conversation.controlStream.StreamID())] = conversation
}

func (m *conversationsManager) getConversation(id util.ConversationID) (*Conversation, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	conv, ok := m.conversations[id]
	return conv, ok
}

func (m * conversationsManager) removeConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.conversations, util.ConversationID(conversation.controlStream.StreamID()))
}

type channelsManager struct {
	channels map[util.ChannelID]Channel
	lock sync.Mutex
}

func newChannelsManager() *channelsManager {
	return &channelsManager{ channels: make(map[util.ChannelID]Channel)}
}

func (m *channelsManager) addChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.channels[util.ChannelID(channel.ChannelID())] = channel
}

func (m *channelsManager) getChannel(id util.ChannelID) (Channel, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	channel, ok := m.channels[id]
	return channel, ok
}

func (m * channelsManager) removeChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.channels, util.ChannelID(channel.ChannelID()))
}

func (m *channelsManager) onChannelClose(channel Channel) {
	m.removeChannel(channel)
}