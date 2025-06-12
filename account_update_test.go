package fraudsdkgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountUpdateWithAuthentication(t *testing.T) {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}

	event := NewAccountUpdateEvent("test-account", AccountUpdateWithAuthentication(authentication))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Authentication)
	assert.Equal(t, authenticationMode, *event.Authentication.Mode)
	assert.Equal(t, authenticationSocialProvider, *event.Authentication.SocialProvider)
	assert.Equal(t, authenticationType, *event.Authentication.Type)
}

func TestAccountUpdateWithSession(t *testing.T) {
	sessionID := "123456"
	createdAt := "1970-01-01T00:00:00Z"
	session := Session{
		ID:        &sessionID,
		CreatedAt: &createdAt,
	}

	event := NewAccountUpdateEvent("test-account", AccountUpdateWithSession(session))
	assert.NotNil(t, event)
	assert.NotNil(t, event.Session)
	assert.Equal(t, sessionID, *event.Session.ID)
	assert.Equal(t, createdAt, *event.Session.CreatedAt)
}

func TestAccountUpdateWithUser(t *testing.T) {
	name := "Élysée Palace"
	line1 := "55 Rue du Faubourg Saint-Honoré"
	line2 := "2nd floor"
	city := "Paris"
	countryCode := "FR"
	regionCode := "75"
	zipCode := "75008"
	userAddress := Address{
		City:        &city,
		CountryCode: &countryCode,
		Line1:       &line1,
		Line2:       &line2,
		Name:        &name,
		RegionCode:  &regionCode,
		ZipCode:     &zipCode,
	}

	userID := "123456"
	createdAt := "1970-01-01T00:00:00Z"
	firstName := "Data"
	lastName := "Dome"
	title := "mrs"
	phone := "+33978787878"
	email := "mail@example.com"
	user := User{
		ID:        userID,
		Address:   &userAddress,
		CreatedAt: &createdAt,
		Email:     &email,
		FirstName: &firstName,
		LastName:  &lastName,
		Phone:     &phone,
		Title:     &title,
	}

	event := NewAccountUpdateEvent("test-account", AccountUpdateWithUser(user))
	assert.NotNil(t, event)
	assert.NotNil(t, event.User)
	assert.NotNil(t, event.User.Address)
	assert.Equal(t, name, *event.User.Address.Name)
	assert.Equal(t, line1, *event.User.Address.Line1)
	assert.Equal(t, line2, *event.User.Address.Line2)
	assert.Equal(t, city, *event.User.Address.City)
	assert.Equal(t, countryCode, *event.User.Address.CountryCode)
	assert.Equal(t, regionCode, *event.User.Address.RegionCode)
	assert.Equal(t, zipCode, *event.User.Address.ZipCode)
	assert.Equal(t, createdAt, *event.User.CreatedAt)
	assert.Equal(t, firstName, *event.User.FirstName)
	assert.Equal(t, lastName, *event.User.LastName)
	assert.Equal(t, title, *event.User.Title)
	assert.Equal(t, phone, *event.User.Phone)
	assert.Equal(t, email, *event.User.Email)
	assert.Equal(t, userID, event.User.ID)
}

func TestNewAccountUpdateEvent(t *testing.T) {
	event := NewAccountUpdateEvent("test-account")
	assert.NotNil(t, event)
	assert.Equal(t, "test-account", event.Account)
}

func ExampleAccountUpdateWithAuthentication() {
	authenticationMode := Password
	authenticationSocialProvider := Google
	authenticationType := Social
	authentication := Authentication{
		Mode:           &authenticationMode,
		SocialProvider: &authenticationSocialProvider,
		Type:           &authenticationType,
	}
	event := NewAccountUpdateEvent("test-account", AccountUpdateWithAuthentication(authentication))

	fmt.Println(*event.Authentication.Mode)
	fmt.Println(*event.Authentication.SocialProvider)
	fmt.Println(*event.Authentication.Type)
	// Output:
	// password
	// google
	// social
}

func ExampleAccountUpdateWithSession() {
	sessionID := "123456"
	session := Session{
		ID: &sessionID,
	}
	event := NewAccountUpdateEvent("test-account", AccountUpdateWithSession(session))

	fmt.Println(*event.Session.ID)
	// Output: 123456
}

func ExampleAccountUpdateWithUser() {
	user := User{}
	user.ID = "123456"
	event := NewAccountUpdateEvent("test-account", AccountUpdateWithUser(user))

	fmt.Println(event.User.ID)
	// Output: 123456
}
