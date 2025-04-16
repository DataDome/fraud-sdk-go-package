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

// getTruncationSize returns the maximal size allowed for a given [ApiFields]
func getTruncationSize(key ApiFields) int {
	switch key {
	case SecCHDeviceMemory, SecCHUAMobile:
		return 8
	case SecCHUAArch:
		return 16
	case SecCHUAPlatform:
		return 32
	case ContentType:
		return 64
	case ClientID, AcceptCharset, AcceptEncoding, Connection, From, SecCHUA, SecCHUAModel, XRealIP:
		return 128
	case AcceptLanguage, SecCHUAFullVersionList:
		return 256
	case Origin, ServerHostname, Accept, Host:
		return 512
	case XForwardedForIP:
		return -512
	case UserAgent:
		return 768
	case Referer:
		return 1024
	case Request:
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
func truncatePointerValue(key ApiFields, value string) *string {
	var result *string
	if value != "" {
		truncatedValue := truncateValue(key, value)
		result = &truncatedValue
	}
	return result
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
