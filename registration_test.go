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

func TestRegistrationWithStatus(t *testing.T) {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithStatus(RegistrationSucceeded))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Status)
	assert.Equal(t, RegistrationSucceeded, *event.Status)
}

func TestRegistrationWithFailReason(t *testing.T) {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithFailReason(DuplicatedAccount))
	assert.NotNil(t, event)
	assert.NotNil(t, event.FailReason)
	assert.Equal(t, DuplicatedAccount, *event.FailReason)
}

func TestRegistrationWithAccountType(t *testing.T) {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithAccountType(CustomerAccountType))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountType)
	assert.Equal(t, CustomerAccountType, *event.AccountType)
}

func TestRegistrationWithPartnerID(t *testing.T) {
	partnerID := "partner-123"
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithPartnerID(partnerID))
	assert.NotNil(t, event)
	assert.NotNil(t, event.PartnerID)
	assert.Equal(t, partnerID, *event.PartnerID)
}

func TestRegistrationWithCustomFields(t *testing.T) {
	fieldType := EmailCustomFieldType
	isPii := true
	fields := []CustomField{
		{Name: "referral", Value: "friend@example.com", Type: &fieldType, IsPii: &isPii},
	}

	event := NewRegistrationEvent("test-account", User{}, RegistrationWithCustomFields(fields))
	assert.NotNil(t, event)
	assert.Len(t, event.CustomFields, 1)
	assert.Equal(t, "referral", event.CustomFields[0].Name)
	assert.Equal(t, "friend@example.com", event.CustomFields[0].Value)
	assert.Equal(t, EmailCustomFieldType, *event.CustomFields[0].Type)
	assert.Equal(t, true, *event.CustomFields[0].IsPii)
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

func ExampleRegistrationWithStatus() {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithStatus(RegistrationSucceeded))

	fmt.Println(*event.Status)
	// Output: succeeded
}

func ExampleRegistrationWithFailReason() {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithFailReason(DuplicatedAccount))

	fmt.Println(*event.FailReason)
	// Output: duplicatedAccount
}

func ExampleRegistrationWithAccountType() {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithAccountType(CustomerAccountType))

	fmt.Println(*event.AccountType)
	// Output: customer
}

func ExampleRegistrationWithPartnerID() {
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithPartnerID("partner-123"))

	fmt.Println(*event.PartnerID)
	// Output: partner-123
}

func ExampleRegistrationWithCustomFields() {
	fieldType := EmailCustomFieldType
	fields := []CustomField{
		{Name: "referral", Value: "friend@example.com", Type: &fieldType},
	}
	event := NewRegistrationEvent("test-account", User{}, RegistrationWithCustomFields(fields))

	fmt.Println(event.CustomFields[0].Name)
	fmt.Println(event.CustomFields[0].Value)
	// Output:
	// referral
	// friend@example.com
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
