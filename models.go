package fraudsdkgo

import (
	"net/http"
)

// Client is used to interact with the DataDome's Account Protect API.
// This structure contains all the informations specified through the [ClientOption]'s functions.
type Client struct {
	Endpoint    string
	FraudAPIKey string
	Timeout     int

	httpClient    *http.Client
	moduleName    string
	moduleVersion string
}

// Event describes the methods that need to be implemented to create a new event type.
type Event interface {
	Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error)
	Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error)
}

// AllowedRequestPayload describes the allowed request payloads to perform a request
// to the Account Protect API.
type AllowedRequestPayload interface {
	LoginRequestPayload | RegistrationRequestPayload | AccountUpdateRequestPayload | PasswordUpdateRequestPayload
}

// Operation describes the available operations related to fraud protection that can be performed.
type Operation string

const (
	ValidateOperation Operation = "validate"
	CollectOperation  Operation = "collect"
)

// Action describes the available actions that can be protected.
type Action string

const (
	AccountUpdate  Action = "account-update"
	Login          Action = "login"
	Registration   Action = "registration"
	PasswordUpdate Action = "password-update"
)

// ResponseStatus describes the possible status outcome.
type ResponseStatus string

const (
	OK      ResponseStatus = "ok"
	Failure ResponseStatus = "failure"
	Timeout ResponseStatus = "timeout"
)

// LoginStatus describes the possible status of an action.
type LoginStatus string

const (
	Failed    LoginStatus = "failed"
	Succeeded LoginStatus = "succeeded"
)

// ResponseAction describes the possible recommendations from the Account Protect API.
type ResponseAction string

const (
	Deny      ResponseAction = "deny"
	Review    ResponseAction = "review"
	Challenge ResponseAction = "challenge"
	Allow     ResponseAction = "allow"
)

// AuthenticationType describes the possible type of authentication.
type AuthenticationType string

const (
	OtherAuthenticationType AuthenticationType = "other"
	Local                   AuthenticationType = "local"
	Social                  AuthenticationType = "social"
)

// AuthenticationMode describes the possible mode of authentication.
type AuthenticationMode string

const (
	OtherAuthenticationMode AuthenticationMode = "other"
	Biometric               AuthenticationMode = "biometric"
	Mail                    AuthenticationMode = "mail"
	MFA                     AuthenticationMode = "mfa"
	OTP                     AuthenticationMode = "otp"
	Password                AuthenticationMode = "password"
)

// AuthenticationSocialProvider desribes the possible social provider used for the authentication.
type AuthenticationSocialProvider string

const (
	OtherAuthenticationSocialProvider AuthenticationSocialProvider = "other"
	Amazon                            AuthenticationSocialProvider = "amazon"
	Apple                             AuthenticationSocialProvider = "apple"
	Facebook                          AuthenticationSocialProvider = "facebook"
	Github                            AuthenticationSocialProvider = "github"
	Google                            AuthenticationSocialProvider = "google"
	Linkedin                          AuthenticationSocialProvider = "linkedin"
	Microsoft                         AuthenticationSocialProvider = "microsoft"
	Twitter                           AuthenticationSocialProvider = "twitter"
	Yahoo                             AuthenticationSocialProvider = "yahoo"
)

const (
	DefaultEndpointValue      string = "https://account-api.datadome.co"
	DefaultTimeoutValue       int    = 1500
	defaultModuleNameValue    string = "Fraud SDK Go"
	defaultModuleVersionValue string = "1.1.1"
)

// Header is used to store the information from the incoming request.
type Header struct {
	Accept                 string  `json:"accept"`
	AcceptCharset          string  `json:"acceptCharset"`
	AcceptEncoding         string  `json:"acceptEncoding"`
	AcceptLanguage         string  `json:"acceptLanguage"`
	Addr                   string  `json:"addr"`
	ClientID               string  `json:"clientID"`
	Connection             string  `json:"connection"`
	ContentType            string  `json:"contentType"`
	From                   string  `json:"from"`
	Host                   string  `json:"host"`
	Method                 string  `json:"method"`
	Referer                string  `json:"referer"`
	Request                string  `json:"request"`
	Origin                 string  `json:"origin"`
	Port                   int     `json:"port"`
	Protocol               string  `json:"protocol"`
	SecCHUA                *string `json:"secCHUA,omitempty"`
	SecCHUAMobile          *string `json:"secCHUAMobile,omitempty"`
	SecCHUAPlatform        *string `json:"secCHUAPlatform,omitempty"`
	SecCHUAArch            *string `json:"secCHUAArch,omitempty"`
	SecCHUAFullVersionList *string `json:"secCHUAFullVersionList,omitempty"`
	SecCHUAModel           *string `json:"secCHUAModel,omitempty"`
	SecCHDeviceMemory      *string `json:"secCHDeviceMemory,omitempty"`
	ServerHostname         string  `json:"serverHostname"`
	UserAgent              string  `json:"userAgent"`
	XForwardedForIP        string  `json:"xForwardedForIp"`
	XRealIP                string  `json:"xRealIP"`
}

// RequestMetadata is used to specify the fields of the [Header] structure that need to be override.
type RequestMetadata struct {
	Accept                 *string
	AcceptCharset          *string
	AcceptEncoding         *string
	AcceptLanguage         *string
	Addr                   *string
	ClientID               *string
	Connection             *string
	ContentType            *string
	From                   *string
	Host                   *string
	Method                 *string
	Referer                *string
	Request                *string
	Origin                 *string
	Port                   *int
	Protocol               *string
	SecCHUA                *string
	SecCHUAMobile          *string
	SecCHUAPlatform        *string
	SecCHUAArch            *string
	SecCHUAFullVersionList *string
	SecCHUAModel           *string
	SecCHDeviceMemory      *string
	ServerHostname         *string
	UserAgent              *string
	XForwardedForIP        *string
	XRealIP                *string
}

// Module is used to store the information about the module that send the [AllowedRequestPayload].
type Module struct {
	RequestTimeMicros int64  `json:"requestTimeMicros"`
	Name              string `json:"name"`
	Version           string `json:"version"`
}

// Session is used to store the information about the user's session.
type Session struct {
	ID        *string `json:"id,omitempty"`
	CreatedAt *string `json:"createdAt,omitempty"`
}

// Address is used to store the address information of a user.
type Address struct {
	City        *string `json:"city,omitempty"`
	CountryCode *string `json:"countryCode,omitempty"`
	Line1       *string `json:"line1,omitempty"`
	Line2       *string `json:"line2,omitempty"`
	Name        *string `json:"name,omitempty"`
	RegionCode  *string `json:"regionCode,omitempty"`
	ZipCode     *string `json:"zipCode,omitempty"`
}

// Location is used to describe the user's location.
type Location struct {
	City        *string `json:"city,omitempty"`
	Country     *string `json:"country,omitempty"`
	CountryCode *string `json:"countryCode,omitempty"`
}

// Authentication is used to describe the user's authentication informations.
type Authentication struct {
	Mode           *AuthenticationMode           `json:"mode,omitempty"`
	SocialProvider *AuthenticationSocialProvider `json:"socialProvider,omitempty"`
	Type           *AuthenticationType           `json:"type,omitempty"`
}

// User is used to store the information of a user.
type User struct {
	ID             string          `json:"id"`
	Address        *Address        `json:"address,omitempty"`
	Authentication *Authentication `json:"authentication,omitempty"`
	CreatedAt      *string         `json:"createdAt,omitempty"`
	DisplayName    *string         `json:"displayName,omitempty"`
	Description    *string         `json:"description,omitempty"`
	Email          *string         `json:"email,omitempty"`
	ExternalURLs   *[]string       `json:"externalUrls,omitempty"`
	FirstName      *string         `json:"firstName,omitempty"`
	LastName       *string         `json:"lastName,omitempty"`
	Phone          *string         `json:"phone,omitempty"`
	PictureURLs    *[]string       `json:"pictureUrls,omitempty"`
	Title          *string         `json:"title,omitempty"`
}

// PasswordUpdateReason describes the possible reasons for updating a password.
type PasswordUpdateReason string

const (
	ForcedReset    PasswordUpdateReason = "forcedReset"
	ForgotPassword PasswordUpdateReason = "forgotPassword"
	UserUpdate     PasswordUpdateReason = "userUpdate"
)

// PasswordUpdateReason describes the possible status when updating a password.
type PasswordUpdateStatus string

const (
	PasswordUpdateAttempted   PasswordUpdateStatus = "attempted"
	PasswordUpdateFailed      PasswordUpdateStatus = "failed"
	PasswordUpdateSucceeded   PasswordUpdateStatus = "succeeded"
	PasswordUpdateLinkExpired PasswordUpdateStatus = "linkExpired"
)

// CommonRequestPayload describes the common fields for the event's request payloads.
type CommonRequestPayload struct {
	Account string `json:"account"`
	Header  Header `json:"header"`
	Module  Module `json:"module"`
}

// LoginRequestPayload describes the expected fields of the payload to be sent to the
// Account Protect API for a [LoginEvent].
type LoginRequestPayload struct {
	CommonRequestPayload
	Status         LoginStatus     `json:"status"`
	User           *User           `json:"user,omitempty"`
	Session        *Session        `json:"session,omitempty"`
	Authentication *Authentication `json:"authentication,omitempty"`
}

// LoginEvent is used to store the fields for a [Login] event.
type LoginEvent struct {
	Account        string
	Action         Action
	Status         LoginStatus
	User           *User
	Session        *Session
	Authentication *Authentication
}

// RegistrationRequestPayload describes the expected fields of the payload to be sent to the
// Account Protect API for a [RegistrationEvent].
type RegistrationRequestPayload struct {
	CommonRequestPayload
	Session *Session `json:"session,omitempty"`
	User    User     `json:"user"`
}

// RegistrationEvent is used to store the fields for a [Registration] event.
type RegistrationEvent struct {
	Account string
	Action  Action
	Session *Session
	User    User
}

// AccountUpdateEvent is used to store the fields for a [AccountUpdate] event.
type AccountUpdateEvent struct {
	Account string
	Action  Action
	Session *Session
	User    *User
}

// AccountUpdateRequestPayload describes the expected fields of the payload to be sent to the
// Account Protect API for a [AccountUpdateEvent].
type AccountUpdateRequestPayload struct {
	CommonRequestPayload
	Session *Session `json:"session,omitempty"`
	User    *User    `json:"user,omitempty"`
}

// PasswordUpdateEvent is used to store the fields for a [PasswordUpdate] event.
type PasswordUpdateEvent struct {
	Account string
	Action  Action
	Reason  PasswordUpdateReason
	Status  PasswordUpdateStatus
	Session *Session
	User    User
}

// PasswordUpdateRequestPayload describes the expected fields of the payload to be sent to the
// Account Protect API for a [PasswordUpdateEvent].
type PasswordUpdateRequestPayload struct {
	CommonRequestPayload
	Reason  PasswordUpdateReason `json:"reason"`
	Session *Session             `json:"session,omitempty"`
	Status  PasswordUpdateStatus `json:"status"`
	User    User                 `json:"user"`
}

// SuccessResponsePayload is used for success response returned by the Account Protect API.
type SuccessResponsePayload struct {
	Action   ResponseAction `json:"action"`
	Status   ResponseStatus
	Reasons  []string  `json:"reasons,omitempty"`
	EventID  *string   `json:"eventId,omitempty"`
	IP       *string   `json:"ip,omitempty"`
	Location *Location `json:"location,omitempty"`
	Score    *int      `json:"score,omitempty"`
}

// ErrorInfo is used to provide more precision about the error returned by the Account Protect API.
type ErrorInfo struct {
	Field string `json:"field,omitempty"`
	Error string `json:"error,omitempty"`
}

// ErrorResponsePayload is used for error response returned by the Account Protect API.
type ErrorResponsePayload struct {
	Message *string     `json:"message,omitempty"`
	Errors  []ErrorInfo `json:"errors,omitempty"`
}

// ResponsePayload describes the fields that can be returned from the Account Protect API.
type ResponsePayload struct {
	SuccessResponsePayload
	ErrorResponsePayload
}
