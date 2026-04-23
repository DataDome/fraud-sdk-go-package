package fraudsdkgo

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ApiFields describes the fields expected for the [AllowedRequestPayload]
type ApiFields string

const (
	Accept                 ApiFields = "Accept"
	AcceptCharset          ApiFields = "AcceptCharset"
	AcceptEncoding         ApiFields = "AcceptEncoding"
	AcceptLanguage         ApiFields = "AcceptLanguage"
	ClientID               ApiFields = "ClientID"
	Connection             ApiFields = "Connection"
	ContentType            ApiFields = "ContentType"
	From                   ApiFields = "From"
	Host                   ApiFields = "Host"
	Origin                 ApiFields = "Origin"
	Referer                ApiFields = "Referer"
	Request                ApiFields = "Request"
	SecCHDeviceMemory      ApiFields = "SecCHDeviceMemory"
	SecCHUA                ApiFields = "SecCHUA"
	SecCHUAArch            ApiFields = "SecCHUAArch"
	SecCHUAFullVersionList ApiFields = "SecCHUAFullVersionList"
	SecCHUAMobile          ApiFields = "SecCHUAMobile"
	SecCHUAModel           ApiFields = "SecCHUAModel"
	SecCHUAPlatform        ApiFields = "SecCHUAPlatform"
	ServerHostname         ApiFields = "ServerHostname"
	UserAgent              ApiFields = "UserAgent"
	XForwardedForIP        ApiFields = "XForwardedForIP"
	XRealIP                ApiFields = "XRealIP"
)

const (
	AccountField            ApiFields = "account"
	AccountTargetField      ApiFields = "accountTarget"
	AddressCityField        ApiFields = "addressCity"
	AddressCountryCodeField ApiFields = "addressCountryCode"
	AddressLine1Field       ApiFields = "addressLine1"
	AddressLine2Field       ApiFields = "addressLine2"
	AddressNameField        ApiFields = "addressName"
	AddressRegionCodeField  ApiFields = "addressRegionCode"
	AddressZipCodeField     ApiFields = "addressZipCode"
	ContentField            ApiFields = "content"
	CustomFieldNameField    ApiFields = "customFieldName"
	CustomFieldValueField   ApiFields = "customFieldValue"
	EventNameField          ApiFields = "eventName"
	PartnerIDField          ApiFields = "partnerId"
	SessionIDField          ApiFields = "sessionId"
	UserDescriptionField    ApiFields = "userDescription"
	UserDisplayNameField    ApiFields = "userDisplayName"
	UserEmailField          ApiFields = "userEmail"
	UserFirstNameField      ApiFields = "userFirstName"
	UserIDField             ApiFields = "userId"
	UserLastNameField       ApiFields = "userLastName"
	UserPhoneField          ApiFields = "userPhone"
	UserURLField            ApiFields = "userUrl"
)

const (
	MaxCustomFields = 5  // customFields maxItems
	MaxURLItems     = 10 // pictureUrls / externalUrls maxItems
)

// getTruncationSize returns the maximal size allowed for a given [ApiFields]
func getTruncationSize(key ApiFields) int {
	switch key {
	case SecCHDeviceMemory, SecCHUAMobile:
		return 8
	case AddressCountryCodeField:
		return 2
	case AddressRegionCodeField, AddressZipCodeField:
		return 15
	case SecCHUAArch, UserPhoneField:
		return 16
	case EventNameField:
		return 20
	case CustomFieldNameField:
		return 25
	case SecCHUAPlatform:
		return 32
	case UserFirstNameField, UserLastNameField, AddressNameField:
		return 50
	case ContentType:
		return 64
	case UserDisplayNameField:
		return 100
	case ClientID, AcceptCharset, AcceptEncoding, Connection, From, SecCHUA, SecCHUAModel, XRealIP:
		return 128
	case SessionIDField, AddressLine1Field, AddressLine2Field, AddressCityField:
		return 255
	case AcceptLanguage, SecCHUAFullVersionList, CustomFieldValueField:
		return 256
	case AccountField, PartnerIDField, AccountTargetField, UserIDField, UserEmailField, UserDescriptionField:
		return 320
	case Origin, ServerHostname, Accept, Host:
		return 512
	case XForwardedForIP:
		return -512
	case UserAgent:
		return 768
	case Referer, ContentField:
		return 1024
	case Request, UserURLField:
		return 2048
	}

	return 0
}

// truncateValue returns the truncated value of the given key.
// If the value does not need to be truncated, it remains unchanged.
func truncateValue(key ApiFields, value string) string {
	if value == "" {
		return ""
	}

	limit := getTruncationSize(key)
	if limit < 0 && len(value) > (-1*limit) {
		limit *= -1
		value = value[len(value)-limit:]
	} else if limit > 0 && len(value) > limit {
		value = value[:limit]
	}

	return value
}

// truncatePointerValue returns a pointer of the truncated value of the given key.
// If the value does not need to be truncated, it remains unchanged.
// Returns nil if value is nil or points to an empty string.
func truncatePointerValue(key ApiFields, value *string) *string {
	if value == nil || *value == "" {
		return nil
	}
	truncated := truncateValue(key, *value)
	return &truncated
}

// capAndTruncateURLs caps a URL slice to [MaxURLItems] and truncates each URL to [UserURLField] max length.
func capAndTruncateURLs(urls *[]string) *[]string {
	if urls == nil {
		return nil
	}
	items := *urls
	if len(items) > MaxURLItems {
		items = items[:MaxURLItems]
	}
	result := make([]string, len(items))
	for i, u := range items {
		result[i] = truncateValue(UserURLField, u)
	}
	return &result
}

// getClientId retrieves the ClientID from the incoming request.
// It uses the value of the `X-DataDome-ClientID` if the session by header feature is used.
// It reads the `DataDome` cookie value otherwise.
func getClientId(r *http.Request) string {
	clientIDHeaders := r.Header.Get("x-datadome-clientid")
	if len(clientIDHeaders) > 0 {
		return clientIDHeaders
	}

	cookie, err := r.Cookie("datadome")
	if err == nil {
		return cookie.Value
	}

	return ""
}

// getIP returns the IP of the emitter from the RemoteAddr field of the request.
func getIP(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	return ip, err
}

// getProtocol returns the protocol of the request.
// It uses the `X-Forwarded-Proto` header value if the value is correct (i.e. `http` or `https`).
// It checks the TLS field of the request afterwards.
func getProtocol(r *http.Request) string {
	proto := "http"
	xForwardedProto := r.Header.Get("x-forwarded-proto")
	if strings.EqualFold(xForwardedProto, "http") || strings.EqualFold(xForwardedProto, "https") {
		proto = xForwardedProto
	} else if r.TLS != nil {
		proto = "https"
	}

	return proto
}

// getURL returns the path and the query parameters (if present) of the request
func getURL(r *http.Request) string {
	if r.URL.RawQuery != "" {
		return r.URL.Path + "?" + r.URL.RawQuery
	} else {
		return r.URL.Path
	}
}

// getPort returns the port requested
func getPort(r *http.Request) int {
	if r.Host == "" {
		return -1
	}
	_, stringPort, err := net.SplitHostPort(r.Host)
	if err != nil {
		return -1
	}
	port, err := strconv.Atoi(stringPort)
	if err != nil {
		return -1
	}
	return port
}

// useMetadata returns the value of val2 if not nil.
// It returns val1 otherwise.
func useMetadata[T comparable](val1 T, val2 *T) T {
	if val2 != nil {
		return *val2
	}
	return val1
}
