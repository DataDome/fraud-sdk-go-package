package fraudsdkgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistrationWithAuthentication(t *testing.T) {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}

	event := NewRegistrationEvent("test-account", User{}, RegistrationWithAuthentication(authentication))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Authentication)
	assert.Equal(t, authenticationMode, *event.Authentication.Mode)
	assert.Equal(t, authenticationSocialProvider, *event.Authentication.SocialProvider)
	assert.Equal(t, authenticationType, *event.Authentication.Type)
}

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

func ExampleRegistrationWithAuthentication() {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}

	event := NewRegistrationEvent("test-account", User{}, RegistrationWithAuthentication(authentication))

	fmt.Println(*event.Authentication.Mode)
	fmt.Println(*event.Authentication.SocialProvider)
	fmt.Println(*event.Authentication.Type)
	// Output:
	// password
	// google
	// social
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
