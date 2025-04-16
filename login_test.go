package fraudsdkgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginWithUser(t *testing.T) {
	userID := "123456"
	user := User{
		ID: userID,
	}

	event := NewLoginEvent("test-account", Failed, LoginWithUser(user))
	assert.NotNil(t, event)
	assert.NotNil(t, event.User)
	assert.Equal(t, userID, event.User.ID)
}

func TestLoginWithSession(t *testing.T) {
	sessionID := "123456"
	createdAt := "1970-01-01T00:00:00Z"
	session := Session{
		ID:        &sessionID,
		CreatedAt: &createdAt,
	}

	event := NewLoginEvent("test-account", Failed, LoginWithSession(session))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Session)
	assert.Equal(t, sessionID, *event.Session.ID)
	assert.Equal(t, createdAt, *event.Session.CreatedAt)
}

func TestLoginWithAuthentication(t *testing.T) {
	authenticationMode := OtherAuthenticationMode
	authenticationSocialProvider := OtherAuthenticationSocialProvider
	authenticationType := OtherAuthenticationType
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}

	event := NewLoginEvent("test-account", Failed, LoginWithAuthentication(authentication))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Authentication)
	assert.Equal(t, *authentication.Mode, *event.Authentication.Mode)
	assert.Equal(t, *authentication.Type, *event.Authentication.Type)
	assert.Equal(t, *authentication.SocialProvider, *event.Authentication.SocialProvider)
}

func TestNewLoginEvent(t *testing.T) {
	event := NewLoginEvent("test-account", Failed)
	assert.NotNil(t, event)
	assert.Equal(t, "test-account", event.Account)
	assert.Equal(t, Failed, event.Status)
}

func ExampleLoginWithUser() {
	user := User{
		ID: "123456",
	}
	event := NewLoginEvent("test-account", Failed, LoginWithUser(user))

	fmt.Println(event.User.ID)
	// Output: 123456
}

func ExampleLoginWithSession() {
	sessionID := "123456"
	session := Session{
		ID: &sessionID,
	}
	event := NewLoginEvent("test-account", Failed, LoginWithSession(session))

	fmt.Println(*event.Session.ID)
	// Output: 123456
}

func ExampleLoginWithAuthentication() {
	authenticationMode := OtherAuthenticationMode
	authenticationSocialProvider := OtherAuthenticationSocialProvider
	authenticationType := OtherAuthenticationType
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}
	event := NewLoginEvent("test-account", Failed, LoginWithAuthentication(authentication))

	fmt.Println(*event.Authentication.Mode)
	// Output: other
}
