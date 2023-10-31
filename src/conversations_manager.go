package ssh3

import (
	"sync"

	"github.com/quic-go/quic-go/http3"
)

type ConversationID uint64

type conversationsManager struct {
	connection http3.StreamCreator
	conversations map[ConversationID]*Conversation
	lock sync.Mutex
}

func newConversationManager(connection http3.StreamCreator) *conversationsManager {
	return &conversationsManager{ connection: connection, conversations: make(map[ConversationID]*Conversation)}
}

func (m *conversationsManager) addConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.conversations[ConversationID(conversation.controlStream.StreamID())] = conversation
}

func (m *conversationsManager) getConversation(id ConversationID) (*Conversation, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	conv, ok := m.conversations[id]
	return conv, ok
}

func (m * conversationsManager) removeConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.conversations, ConversationID(conversation.controlStream.StreamID()))
}