package fraudsdkgo

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setup() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/ping", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Hello", "World")
	request.Header.Set("X-Test", "123")

	return request
}

func TestGetClientId_WithSessionByHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/this-is-the-way", nil)
	req.Header.Set("x-datadome-clientid", "123456")

	result := getClientId(req)

	assert.Equal(t, "123456", result)
}

func TestGetClientId_WithCookie(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/this-is-the-way", nil)
	cookie := &http.Cookie{
		Name:  "datadome",
		Value: "some_value",
	}
	req.AddCookie(cookie)

	result := getClientId(req)

	assert.Equal(t, "some_value", result)
}

func TestGetClientId_WithoutCookie(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/this-is-the-way", nil)

	result := getClientId(req)

	assert.Equal(t, "", result)
}

func TestGetIP(t *testing.T) {
	request := setup()

	result, err := getIP(request)
	assert.Equal(t, "127.0.0.1", result)
	assert.Equal(t, nil, err)
}

func TestGetPort(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected int
	}{
		{"Valid port", "example.com:8080", 8080},
		{"Missing port", "example.com", -1},
		{"Empty host", "", -1},
		{"Localhost with port", "localhost:3000", 3000},
		{"Localhost with invalid port", "localhost:aaaa", -1},
		{"IPv4 address with port", "192.168.1.1:5000", 5000},
		{"IPv6 address with port", "[2001:db8::1]:9090", 9090},
		{"IPv6 without port", "[2001:db8::1]", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Host: tc.host}
			got := getPort(r)
			assert.Equal(t, tc.expected, got, "getPort(%q)", tc.host)
		})
	}
}

func TestGetProtocol(t *testing.T) {
	reqHTTP := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqHTTPSWithTLS := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqHTTPWithXFP := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqHTTPSWithXFP := httptest.NewRequest(http.MethodGet, "http://example.com", nil)

	reqHTTPSWithTLS.TLS = &tls.ConnectionState{}
	reqHTTPWithXFP.Header.Set("X-Forwarded-Proto", "http")
	reqHTTPSWithXFP.Header.Set("X-Forwarded-Proto", "https")

	tests := []struct {
		want  string
		input *http.Request
	}{
		{want: "http", input: reqHTTP},
		{want: "http", input: reqHTTPWithXFP},
		{want: "https", input: reqHTTPSWithTLS},
		{want: "https", input: reqHTTPSWithXFP},
	}

	for _, tc := range tests {
		got := getProtocol(tc.input)
		assert.Equal(t, tc.want, got)
	}
}

func TestGetURL(t *testing.T) {
	request := setup()

	result := getURL(request)
	assert.Equal(t, "/ping", result)

	request = httptest.NewRequest(http.MethodGet, "/ping?a=b", nil)
	result = getURL(request)
	assert.Equal(t, "/ping?a=b", result)
}

func TestTruncateValue(t *testing.T) {
	type Header struct {
		Key   ApiFields
		Value string
	}
	fakeCommonValue := strings.Repeat("a", 3000)
	fakeEndXFFValue := strings.Repeat("b", 512)
	fakeXFFValue := fakeCommonValue + fakeEndXFFValue

	tests := []struct {
		want  int
		input Header
	}{
		{want: 8, input: Header{Key: HeaderSecCHUAMobile, Value: fakeCommonValue}},
		{want: 16, input: Header{Key: HeaderSecCHUAArch, Value: fakeCommonValue}},
		{want: 32, input: Header{Key: HeaderSecCHUAPlatform, Value: fakeCommonValue}},
		{want: 64, input: Header{Key: HeaderContentType, Value: fakeCommonValue}},
		{want: 128, input: Header{Key: HeaderSecCHUA, Value: fakeCommonValue}},
		{want: 256, input: Header{Key: HeaderAcceptLanguage, Value: fakeCommonValue}},
		{want: 512, input: Header{Key: HeaderOrigin, Value: fakeCommonValue}},
		{want: 768, input: Header{Key: HeaderUserAgent, Value: fakeCommonValue}},
		{want: 1024, input: Header{Key: HeaderReferer, Value: fakeCommonValue}},
		{want: 2048, input: Header{Key: HeaderRequest, Value: fakeCommonValue}},
		{want: 3000, input: Header{Key: "RequestModuleName", Value: fakeCommonValue}},
		{want: 512, input: Header{Key: HeaderXForwardedForIp, Value: fakeXFFValue}},
		{want: 0, input: Header{Key: "SomeHeader", Value: ""}},
	}

	for _, tc := range tests {
		got := truncateValue(tc.input.Key, tc.input.Value)
		assert.Equal(t, tc.want, len(got))
		if tc.input.Key == HeaderXForwardedForIp {
			assert.Equal(t, fakeEndXFFValue, got)
		}
	}
}

func TestTruncatePointerValue(t *testing.T) {
	nilPointer := truncatePointerValue(HeaderSecCHUA, nil)
	assert.Nil(t, nilPointer)

	empty := ""
	emptyPointer := truncatePointerValue(HeaderSecCHUA, &empty)
	assert.Nil(t, emptyPointer)

	val := "some_value"
	notNilPointer := truncatePointerValue(HeaderSecCHUA, &val)
	assert.NotNil(t, notNilPointer)
	assert.Equal(t, "some_value", *notNilPointer)
}

func TestUseMetadata(t *testing.T) {
	val1 := "Foo"
	var val2 *string
	result1 := useMetadata(val1, val2)
	assert.Equal(t, "Foo", result1)

	tmp := "Bar"
	val2 = &tmp
	result2 := useMetadata(val1, val2)
	assert.Equal(t, "Bar", result2)
}

func TestPayloadFieldTruncation(t *testing.T) {
	long := strings.Repeat("x", 3000)
	tests := []struct {
		field ApiFields
		want  int
	}{
		{UserAllOfAddressCountryCode, 2},
		{UserAllOfAddressRegionCode, 15},
		{UserAllOfAddressZipCode, 15},
		{UserPhone, 16},
		{CustomActionPayloadEventName, 20},
		{CustomFieldName, 25},
		{UserFirstName, 50},
		{UserLastName, 50},
		{UserAllOfAddressName, 50},
		{UserDisplayName, 100},
		{SessionId, 255},
		{UserAllOfAddressLine1, 255},
		{UserAllOfAddressLine2, 255},
		{UserAllOfAddressCity, 255},
		{CustomFieldValue, 1024},
		{LoginPayloadAccount, 320},
		{LoginPayloadPartnerId, 320},
		{CustomActionPayloadAccountTarget, 320},
		{AccountUpdatePayloadAllOfUserId, 320},
		{AccountUpdatePayloadAllOfUserEmail, 320},
		{AccountUpdatePayloadAllOfUserDescription, 320},
		{CustomActionPayloadContent, 3000},
		{UserPictureUrlsItem, 2048},
	}

	for _, tc := range tests {
		got := truncateValue(tc.field, long)
		assert.Equal(t, tc.want, len(got), "field %s", tc.field)
	}
}

func TestTruncatePointerValue_Truncates(t *testing.T) {
	long := strings.Repeat("a", 500)
	result := truncatePointerValue(LoginPayloadAccount, &long)
	assert.NotNil(t, result)
	assert.Equal(t, 320, len(*result))
}

func TestCapAndTruncateStrings_Nil(t *testing.T) {
	result := capAndTruncateStrings(nil, 10, UserPictureUrlsItem)
	assert.Nil(t, result)
}

func TestCapAndTruncateStrings_CapsAndTruncatesEach(t *testing.T) {
	longURL := strings.Repeat("u", 3000)
	urls := []string{longURL, "short"}
	result := capAndTruncateStrings(urls, 10, UserPictureUrlsItem)
	assert.NotNil(t, result)
	assert.Len(t, result, 2)
	assert.Equal(t, 2048, len(result[0]))
	assert.Equal(t, "short", result[1])
}
