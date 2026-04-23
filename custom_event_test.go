package fraudsdkgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCustomEventWithEventStatus(t *testing.T) {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithEventStatus(CustomEventSucceeded))
	assert.NotNil(t, event)
	assert.NotNil(t, event.EventStatus)
	assert.Equal(t, CustomEventSucceeded, *event.EventStatus)
}

func TestCustomEventWithIsEventCritical(t *testing.T) {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithIsEventCritical(true))
	assert.NotNil(t, event)
	assert.NotNil(t, event.IsEventCritical)
	assert.Equal(t, true, *event.IsEventCritical)
}

func TestCustomEventWithContent(t *testing.T) {
	content := "some content"
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithContent(content))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Content)
	assert.Equal(t, content, *event.Content)
}

func TestCustomEventWithAccountTarget(t *testing.T) {
	target := "target-account"
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAccountTarget(target))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountTarget)
	assert.Equal(t, target, *event.AccountTarget)
}

func TestCustomEventWithSession(t *testing.T) {
	sessionID := "123456"
	createdAt := "1970-01-01T00:00:00Z"
	session := Session{
		ID:        &sessionID,
		CreatedAt: &createdAt,
	}

	event := NewCustomEvent("test-account", "myEvent", CustomEventWithSession(session))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Session)
	assert.Equal(t, sessionID, *event.Session.ID)
	assert.Equal(t, createdAt, *event.Session.CreatedAt)
}

func TestCustomEventWithAccountType(t *testing.T) {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAccountType(CustomerAccountType))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountType)
	assert.Equal(t, CustomerAccountType, *event.AccountType)
}

func TestCustomEventWithUser(t *testing.T) {
	userID := "123456"
	isAuthenticated := true
	user := CustomEventUser{
		User:            User{ID: userID},
		IsAuthenticated: &isAuthenticated,
	}

	event := NewCustomEvent("test-account", "myEvent", CustomEventWithUser(user))
	assert.NotNil(t, event)
	assert.NotNil(t, event.User)
	assert.Equal(t, userID, event.User.ID)
	assert.NotNil(t, event.User.IsAuthenticated)
	assert.Equal(t, isAuthenticated, *event.User.IsAuthenticated)
}

func TestCustomEventWithAuthentication(t *testing.T) {
	authenticationMode := OtherAuthenticationMode
	authenticationSocialProvider := OtherAuthenticationSocialProvider
	authenticationType := OtherAuthenticationType
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}

	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAuthentication(authentication))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Authentication)
	assert.Equal(t, *authentication.Mode, *event.Authentication.Mode)
	assert.Equal(t, *authentication.Type, *event.Authentication.Type)
	assert.Equal(t, *authentication.SocialProvider, *event.Authentication.SocialProvider)
}

func TestCustomEventWithPartnerID(t *testing.T) {
	partnerID := "partner-123"
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithPartnerID(partnerID))
	assert.NotNil(t, event)
	assert.NotNil(t, event.PartnerID)
	assert.Equal(t, partnerID, *event.PartnerID)
}

func TestCustomEventWithCustomFields(t *testing.T) {
	fieldType := StringCustomFieldType
	isPii := false
	fields := []CustomField{
		{Name: "planType", Value: "premium", Type: &fieldType, IsPii: &isPii},
	}

	event := NewCustomEvent("test-account", "myEvent", CustomEventWithCustomFields(fields))
	assert.NotNil(t, event)
	assert.Len(t, event.CustomFields, 1)
	assert.Equal(t, "planType", event.CustomFields[0].Name)
	assert.Equal(t, "premium", event.CustomFields[0].Value)
	assert.NotNil(t, event.CustomFields[0].Type)
	assert.Equal(t, StringCustomFieldType, *event.CustomFields[0].Type)
}

func TestCustomEventWithAccountCreationDate(t *testing.T) {
	date := "2020-01-01T00:00:00Z"
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAccountCreationDate(date))
	assert.NotNil(t, event)
	assert.NotNil(t, event.AccountCreationDate)
	assert.Equal(t, date, *event.AccountCreationDate)
}

func TestNewCustomEvent(t *testing.T) {
	event := NewCustomEvent("test-account", "myEvent")
	assert.NotNil(t, event)
	assert.Equal(t, "test-account", event.Account)
	assert.Equal(t, "myEvent", event.EventName)
	assert.Nil(t, event.EventStatus)
	assert.Nil(t, event.User)
	assert.Nil(t, event.Session)
}

func ExampleCustomEventWithEventStatus() {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithEventStatus(CustomEventSucceeded))

	fmt.Println(*event.EventStatus)
	// Output: succeeded
}

func ExampleCustomEventWithSession() {
	sessionID := "123456"
	session := Session{
		ID: &sessionID,
	}
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithSession(session))

	fmt.Println(*event.Session.ID)
	// Output: 123456
}

func ExampleCustomEventWithUser() {
	userID := "123456"
	user := CustomEventUser{
		User: User{ID: userID},
	}
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithUser(user))

	fmt.Println(event.User.ID)
	// Output: 123456
}

func ExampleCustomEventWithAuthentication() {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAuthentication(authentication))

	fmt.Println(*event.Authentication.Mode)
	fmt.Println(*event.Authentication.SocialProvider)
	fmt.Println(*event.Authentication.Type)
	// Output:
	// password
	// google
	// social
}

func ExampleCustomEventWithIsEventCritical() {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithIsEventCritical(true))

	fmt.Println(*event.IsEventCritical)
	// Output: true
}

func ExampleCustomEventWithContent() {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithContent("some content"))

	fmt.Println(*event.Content)
	// Output: some content
}

func ExampleCustomEventWithAccountTarget() {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAccountTarget("target-account"))

	fmt.Println(*event.AccountTarget)
	// Output: target-account
}

func ExampleCustomEventWithAccountCreationDate() {
	date := "2020-01-01T00:00:00Z"
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAccountCreationDate(date))

	fmt.Println(*event.AccountCreationDate)
	// Output: 2020-01-01T00:00:00Z
}

func ExampleCustomEventWithPartnerID() {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithPartnerID("partner-123"))

	fmt.Println(*event.PartnerID)
	// Output: partner-123
}

func ExampleCustomEventWithCustomFields() {
	fieldType := StringCustomFieldType
	fields := []CustomField{
		{Name: "planType", Value: "premium", Type: &fieldType},
	}
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithCustomFields(fields))

	fmt.Println(event.CustomFields[0].Name)
	fmt.Println(event.CustomFields[0].Value)
	// Output:
	// planType
	// premium
}

func ExampleCustomEventWithAccountType() {
	event := NewCustomEvent("test-account", "myEvent", CustomEventWithAccountType(CustomerAccountType))

	fmt.Println(*event.AccountType)
	// Output: customer
}
