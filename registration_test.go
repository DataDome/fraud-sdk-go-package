package fraudsdkgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistrationWithSession(t *testing.T) {
	sessionID := "123456"
	createdAt := "1970-01-01T00:00:00Z"
	session := Session{
		ID:        &sessionID,
		CreatedAt: &createdAt,
	}

	event := NewRegistrationEvent("test-account", User{}, RegistrationWithSession(session))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Session)
	assert.Equal(t, sessionID, *event.Session.ID)
	assert.Equal(t, createdAt, *event.Session.CreatedAt)
}

func TestNewRegistrationEvent(t *testing.T) {
	event := NewRegistrationEvent("test-account", User{})
	assert.NotNil(t, event)
	assert.NotNil(t, event.User)
	assert.Equal(t, "test-account", event.Account)
}

func ExampleRegistrationWithSession() {
	sessionID := "123456"
	session := Session{
		ID: &sessionID,
	}
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithSession(session))

	fmt.Println(*event.Session.ID)
	// Output: 123456
}
