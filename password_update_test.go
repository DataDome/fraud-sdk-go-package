package fraudsdkgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordUpdateWithSession(t *testing.T) {
	sessionID := "123456"
	createdAt := "1970-01-01T00:00:00Z"
	session := Session{
		ID:        &sessionID,
		CreatedAt: &createdAt,
	}

	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithSession(session))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Session)
	assert.Equal(t, sessionID, *event.Session.ID)
	assert.Equal(t, createdAt, *event.Session.CreatedAt)
}

func TestNewPasswordUpdateEvent(t *testing.T) {
	event := NewPasswordUpdateEvent("test-account", User{}, ForcedReset, PasswordUpdateAttempted)
	assert.NotNil(t, event)
	assert.NotNil(t, event.User)
	assert.Equal(t, ForcedReset, event.Reason)
	assert.Equal(t, PasswordUpdateAttempted, event.Status)
}

func ExamplePasswordUpdateWithSession() {
	sessionID := "123456"
	session := Session{
		ID: &sessionID,
	}
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithSession(session))

	fmt.Println(*event.Session.ID)
	// Output: 123456
}
