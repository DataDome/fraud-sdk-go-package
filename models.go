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
	LoginRequestPayload | RegistrationRequestPayload
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
	Login        Action = "login"
	Registration Action = "registration"
)

// ResponseStatus describes the possible status outcome.
type ResponseStatus string

const (
	OK      ResponseStatus = "ok"
	Failure ResponseStatus = "failure"
	Timeout ResponseStatus = "timeout"
)

// RequestStatus describes the possible status of an action.
type RequestStatus string

const (
	Failed    RequestStatus = "failed"
	Succeeded RequestStatus = "succeeded"
)

// ResponseAction describes the possible recommendations from the Account Protect API.
type ResponseAction string

const (
	Deny      ResponseAction = "deny"
	Review    ResponseAction = "review"
	Challenge ResponseAction = "challenge"
	Allow     ResponseAction = "allow"
)

const (
	DefaultEndpointValue      string = "account-api.datadome.co"
	DefaultTimeoutValue       int    = 1500
	defaultModuleNameValue    string = "Account Protect SDK Go"
	defaultModuleVersionValue string = "1.0.0"
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
	XForwardedForIP        string  `json:"xForwardedForIP"`
	XRealIP                string  `json:"xRealIP"`
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

// User is used to store the information of a user.
type User struct {
	ID        string   `json:"id"`
	Address   *Address `json:"address,omitempty"`
	CreatedAt *string  `json:"createdAt,omitempty"`
	Email     *string  `json:"email,omitempty"`
	FirstName *string  `json:"firstName,omitempty"`
	LastName  *string  `json:"lastName,omitempty"`
	Phone     *string  `json:"phone,omitempty"`
	Title     *string  `json:"title,omitempty"`
}

// LoginRequestPayload describes the expected fields of the payload to be sent to the
// Account Protect API for a [LoginEvent].
type LoginRequestPayload struct {
	Account string        `json:"account"`
	Header  Header        `json:"header"`
	Module  Module        `json:"module"`
	Status  RequestStatus `json:"status"`
}

// LoginEvent is used to store the fields for a [Login] event.
type LoginEvent struct {
	Account string
	Action  Action
	Status  RequestStatus
}

// RegistrationRequestPayload describes the expected fields of the payload to be sent to the
// Account Protect API for a [RegistrationEvent].
type RegistrationRequestPayload struct {
	Account string   `json:"account"`
	Header  Header   `json:"header"`
	Module  Module   `json:"module"`
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

// SuccessResponsePayload is used for success response returned by the Account Protect API.
type SuccessResponsePayload struct {
	Action   ResponseAction `json:"action"`
	Status   ResponseStatus
	Reasons  []string  `json:"reasons,omitempty"`
	EventID  *string   `json:"eventId,omitempty"`
	IP       *string   `json:"ip,omitempty"`
	Location *Location `json:"location,omitempty"`
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
