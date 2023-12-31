package h3sh

import (
	"sync"

	"github.com/francoismichel/h3sh/util"
	"github.com/quic-go/quic-go/http3"
)

type ControlStreamID = uint64

type conversationsManager struct {
	connection    http3.StreamCreator
	conversations map[ControlStreamID]*Conversation
	lock          sync.Mutex
}

func newConversationManager(connection http3.StreamCreator) *conversationsManager {
	return &conversationsManager{connection: connection, conversations: make(map[ControlStreamID]*Conversation)}
}

func (m *conversationsManager) addConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.conversations[uint64(conversation.controlStream.StreamID())] = conversation
}

func (m *conversationsManager) getConversation(id ControlStreamID) (*Conversation, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	conv, ok := m.conversations[id]
	return conv, ok
}

func (m *conversationsManager) removeConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.conversations, uint64(conversation.controlStream.StreamID()))
}

type channelsManager struct {
	channels            map[util.ChannelID]Channel
	danglingDgramQueues map[util.ChannelID]*util.DatagramsQueue
	lock                sync.Mutex
}

func newChannelsManager() *channelsManager {
	return &channelsManager{channels: make(map[util.ChannelID]Channel), danglingDgramQueues: make(map[util.ChannelID]*util.DatagramsQueue)}
}

func (m *channelsManager) addChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if dgramsQueue, ok := m.danglingDgramQueues[channel.ChannelID()]; ok {
		channel.setDgramQueue(dgramsQueue)
		delete(m.danglingDgramQueues, channel.ChannelID())
	}
	m.channels[util.ChannelID(channel.ChannelID())] = channel
}

func (m *channelsManager) addDanglingDatagramsQueue(id util.ChannelID, queue *util.DatagramsQueue) {
	m.lock.Lock()
	defer m.lock.Unlock()
	// let's first check if a channel has recently been added
	if channel, ok := m.channels[id]; ok {
		dgram := queue.Next()
		for ; dgram != nil; dgram = queue.Next() {
			channel.addDatagram(dgram)
		}
	} else {
		m.danglingDgramQueues[id] = queue
	}
}

func (m *channelsManager) getChannel(id util.ChannelID) (Channel, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	channel, ok := m.channels[id]
	return channel, ok
}

func (m *channelsManager) removeChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.channels, util.ChannelID(channel.ChannelID()))
}

func (m *channelsManager) onChannelClose(channel Channel) {
	m.removeChannel(channel)
}
