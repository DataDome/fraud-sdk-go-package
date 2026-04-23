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

func TestPasswordUpdateWithAuthentication(t *testing.T) {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}

	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithAuthentication(authentication))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Authentication)
	assert.Equal(t, authenticationMode, *event.Authentication.Mode)
	assert.Equal(t, authenticationSocialProvider, *event.Authentication.SocialProvider)
	assert.Equal(t, authenticationType, *event.Authentication.Type)
}

func TestPasswordUpdateWithAccountCreationDate(t *testing.T) {
	date := "2020-01-01T00:00:00Z"
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithAccountCreationDate(date))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountCreationDate)
	assert.Equal(t, date, *event.AccountCreationDate)
}

func TestPasswordUpdateWithPartnerID(t *testing.T) {
	partnerID := "partner-123"
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithPartnerID(partnerID))
	assert.NotNil(t, event)
	assert.NotNil(t, event.PartnerID)
	assert.Equal(t, partnerID, *event.PartnerID)
}

func TestPasswordUpdateWithCustomFields(t *testing.T) {
	fieldType := StringCustomFieldType
	isPii := false
	fields := []CustomField{
		{Name: "resetMethod", Value: "email", Type: &fieldType, IsPii: &isPii},
	}

	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithCustomFields(fields))
	assert.NotNil(t, event)
	assert.Len(t, event.CustomFields, 1)
	assert.Equal(t, "resetMethod", event.CustomFields[0].Name)
	assert.Equal(t, "email", event.CustomFields[0].Value)
	assert.Equal(t, StringCustomFieldType, *event.CustomFields[0].Type)
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

func ExamplePasswordUpdateWithAccountCreationDate() {
	date := "2020-01-01T00:00:00Z"
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithAccountCreationDate(date))

	fmt.Println(*event.AccountCreationDate)
	// Output: 2020-01-01T00:00:00Z
}

func ExamplePasswordUpdateWithPartnerID() {
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithPartnerID("partner-123"))

	fmt.Println(*event.PartnerID)
	// Output: partner-123
}

func ExamplePasswordUpdateWithCustomFields() {
	fieldType := StringCustomFieldType
	fields := []CustomField{
		{Name: "resetMethod", Value: "email", Type: &fieldType},
	}
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithCustomFields(fields))

	fmt.Println(event.CustomFields[0].Name)
	fmt.Println(event.CustomFields[0].Value)
	// Output:
	// resetMethod
	// email
}

func ExamplePasswordUpdateWithAuthentication() {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}
	event := NewPasswordUpdateEvent("test-account", User{ID: "123456"}, ForcedReset, PasswordUpdateAttempted, PasswordUpdateWithAuthentication(authentication))

	fmt.Println(*event.Authentication.Mode)
	fmt.Println(*event.Authentication.SocialProvider)
	fmt.Println(*event.Authentication.Type)
	// Output:
	// password
	// google
	// social
}
