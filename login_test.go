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

func TestLoginWithFailReason(t *testing.T) {
	event := NewLoginEvent("test-account", Failed, LoginWithFailReason(WrongPassword))
	assert.NotNil(t, event)
	assert.NotNil(t, event.FailReason)
	assert.Equal(t, WrongPassword, *event.FailReason)
}

func TestLoginWithAccountType(t *testing.T) {
	event := NewLoginEvent("test-account", Failed, LoginWithAccountType(CustomerAccountType))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountType)
	assert.Equal(t, CustomerAccountType, *event.AccountType)
}

func TestLoginWithAccountCreationDate(t *testing.T) {
	date := "2020-01-01T00:00:00Z"
	event := NewLoginEvent("test-account", Failed, LoginWithAccountCreationDate(date))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountCreationDate)
	assert.Equal(t, date, *event.AccountCreationDate)
}

func TestLoginWithPartnerID(t *testing.T) {
	partnerID := "partner-123"
	event := NewLoginEvent("test-account", Failed, LoginWithPartnerID(partnerID))
	assert.NotNil(t, event)
	assert.NotNil(t, event.PartnerID)
	assert.Equal(t, partnerID, *event.PartnerID)
}

func TestLoginWithCustomFields(t *testing.T) {
	fieldType := StringCustomFieldType
	isPii := false
	fields := []CustomField{
		{Name: "planType", Value: "premium", Type: &fieldType, IsPii: &isPii},
	}

	event := NewLoginEvent("test-account", Failed, LoginWithCustomFields(fields))
	assert.NotNil(t, event)
	assert.Len(t, event.CustomFields, 1)
	assert.Equal(t, "planType", event.CustomFields[0].Name)
	assert.Equal(t, "premium", event.CustomFields[0].Value)
	assert.Equal(t, StringCustomFieldType, *event.CustomFields[0].Type)
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

func ExampleLoginWithFailReason() {
	event := NewLoginEvent("test-account", Failed, LoginWithFailReason(WrongPassword))

	fmt.Println(*event.FailReason)
	// Output: wrongPassword
}

func ExampleLoginWithAccountType() {
	event := NewLoginEvent("test-account", Failed, LoginWithAccountType(CustomerAccountType))

	fmt.Println(*event.AccountType)
	// Output: customer
}

func ExampleLoginWithAccountCreationDate() {
	date := "2020-01-01T00:00:00Z"
	event := NewLoginEvent("test-account", Failed, LoginWithAccountCreationDate(date))

	fmt.Println(*event.AccountCreationDate)
	// Output: 2020-01-01T00:00:00Z
}

func ExampleLoginWithPartnerID() {
	event := NewLoginEvent("test-account", Failed, LoginWithPartnerID("partner-123"))

	fmt.Println(*event.PartnerID)
	// Output: partner-123
}

func ExampleLoginWithCustomFields() {
	fieldType := StringCustomFieldType
	fields := []CustomField{
		{Name: "planType", Value: "premium", Type: &fieldType},
	}
	event := NewLoginEvent("test-account", Failed, LoginWithCustomFields(fields))

	fmt.Println(event.CustomFields[0].Name)
	fmt.Println(event.CustomFields[0].Value)
	// Output:
	// planType
	// premium
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
