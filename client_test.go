package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	t.Run("Instantiate client with default values", func(t *testing.T) {
		fraudAPIKey := "your-fraud-api-key"
		c, err := NewClient(fraudAPIKey)

		assert.Nil(t, err)
		assert.Equal(t, DefaultEndpointValue, c.Endpoint)
		assert.Equal(t, defaultModuleNameValue, c.moduleName)
		assert.Equal(t, defaultModuleVersionValue, c.moduleVersion)
		assert.Equal(t, fraudAPIKey, c.FraudAPIKey)
		assert.Equal(t, DefaultTimeoutValue, c.Timeout)

		assert.NotNil(t, c.httpClient)
	})

	t.Run("Error is returned when passing an empty string for the fraud API key", func(t *testing.T) {
		c, err := NewClient("")

		assert.Nil(t, c)
		assert.NotNil(t, err)
		assert.Equal(t, "FraudAPIKey must be defined", err.Error())
	})
}

func setupRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/ping", nil)
	request.Host = "www.example.com"
	request.RemoteAddr = "127.0.0.1:1234"
	request.Method = "GET"
	request.Header.Set("Hello", "world")
	request.Header.Set("user-agent", "über cool mozilla")
	request.Header.Set("referer", "www.example2.com")
	request.Header.Set("accept", "application/json")
	request.Header.Set("accept-encoding", "fr-FR")
	request.Header.Set("accept-charset", "utf8")
	request.Header.Set("accept-language", "fr")
	request.Header.Set("content-type", "application/json")
	request.Header.Set("origin", "www.example.com")
	request.Header.Set("x-forwarded-for", "192.168.10.10, 127.0.0.1")
	request.Header.Set("x-real-ip", "192.168.10.10")
	request.Header.Set("x-forwarded-proto", "http")
	request.Header.Set("connection", "new")
	request.Header.Set("pragma", "no-cache")
	request.Header.Set("cache-control", "max-age=604800")
	request.Header.Set("x-real-ip", "127.0.0.1")
	cookie := &http.Cookie{
		Name:  "datadome",
		Value: "some_value",
	}
	request.AddCookie(cookie)

	return request
}

func TestGetHeader_OnlyRequiredValues(t *testing.T) {
	request := setupRequest()
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	header, err := c.buildHeader(request, &RequestMetadata{})

	assert.Nil(t, err)

	// required fields
	assert.Equal(t, "application/json", header.Accept)
	assert.Equal(t, "utf8", header.AcceptCharset)
	assert.Equal(t, "fr-FR", header.AcceptEncoding)
	assert.Equal(t, "fr", header.AcceptLanguage)
	assert.Equal(t, "127.0.0.1", header.Addr)
	assert.Equal(t, "some_value", header.ClientID)
	assert.Equal(t, "new", header.Connection)
	assert.Equal(t, "application/json", header.ContentType)
	assert.Equal(t, "", header.From)
	assert.Equal(t, "www.example.com", header.Host)
	assert.Equal(t, "GET", header.Method)
	assert.Equal(t, "www.example2.com", header.Referer)
	assert.Equal(t, "/ping", header.Request)
	assert.Equal(t, "www.example.com", header.Origin)
	assert.Equal(t, 80, header.Port)
	assert.Equal(t, "http", header.Protocol)
	assert.Equal(t, "www.example.com", header.ServerHostname)
	assert.Equal(t, "über cool mozilla", header.UserAgent)
	assert.Equal(t, "192.168.10.10, 127.0.0.1", header.XForwardedForIP)
	assert.Equal(t, "127.0.0.1", header.XRealIP)

	// optional fields
	assert.Nil(t, header.SecCHUA)
	assert.Nil(t, header.SecCHUAMobile)
	assert.Nil(t, header.SecCHUAPlatform)
	assert.Nil(t, header.SecCHUAArch)
	assert.Nil(t, header.SecCHUAFullVersionList)
	assert.Nil(t, header.SecCHUAModel)
	assert.Nil(t, header.SecCHDeviceMemory)
}

func TestGetHeader_WithOptionalValues(t *testing.T) {
	request := setupRequest()

	// add optional fields
	request.Header.Set("Sec-CH-UA", `"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"`)
	request.Header.Set("Sec-CH-UA-Mobile", "?0")
	request.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	request.Header.Set("Sec-CH-UA-Arch", `"x86"`)
	request.Header.Set("Sec-CH-UA-Full-Version-List", `"Not.A/Brand";v="8.0.0.0", "Chromium";v="114.0.5735.199", "Google Chrome";v="114.0.5735.199"`)
	request.Header.Set("Sec-CH-UA-Model", "Pixel 3")
	request.Header.Set("Sec-CH-Device-Memory", "8")

	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	header, err := c.buildHeader(request, &RequestMetadata{})

	assert.Nil(t, err)

	// required fields
	assert.Equal(t, "application/json", header.Accept)
	assert.Equal(t, "utf8", header.AcceptCharset)
	assert.Equal(t, "fr-FR", header.AcceptEncoding)
	assert.Equal(t, "fr", header.AcceptLanguage)
	assert.Equal(t, "127.0.0.1", header.Addr)
	assert.Equal(t, "some_value", header.ClientID)
	assert.Equal(t, "new", header.Connection)
	assert.Equal(t, "application/json", header.ContentType)
	assert.Equal(t, "", header.From)
	assert.Equal(t, "www.example.com", header.Host)
	assert.Equal(t, "GET", header.Method)
	assert.Equal(t, "www.example2.com", header.Referer)
	assert.Equal(t, "/ping", header.Request)
	assert.Equal(t, "www.example.com", header.Origin)
	assert.Equal(t, 80, header.Port)
	assert.Equal(t, "http", header.Protocol)
	assert.Equal(t, "www.example.com", header.ServerHostname)
	assert.Equal(t, "über cool mozilla", header.UserAgent)
	assert.Equal(t, "192.168.10.10, 127.0.0.1", header.XForwardedForIP)
	assert.Equal(t, "127.0.0.1", header.XRealIP)

	// optional fields
	assert.NotNil(t, header.SecCHUA)
	assert.Equal(t, `"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"`, *header.SecCHUA)
	assert.NotNil(t, header.SecCHUAMobile)
	assert.Equal(t, "?0", *header.SecCHUAMobile)
	assert.NotNil(t, header.SecCHUAPlatform)
	assert.Equal(t, `"Windows"`, *header.SecCHUAPlatform)
	assert.NotNil(t, header.SecCHUAArch)
	assert.Equal(t, `"x86"`, *header.SecCHUAArch)
	assert.NotNil(t, header.SecCHUAFullVersionList)
	assert.Equal(t, `"Not.A/Brand";v="8.0.0.0", "Chromium";v="114.0.5735.199", "Google Chrome";v="114.0.5735.199"`, *header.SecCHUAFullVersionList)
	assert.NotNil(t, header.SecCHUAModel)
	assert.Equal(t, "Pixel 3", *header.SecCHUAModel)
	assert.NotNil(t, header.SecCHDeviceMemory)
	assert.Equal(t, "8", *header.SecCHDeviceMemory)
}

func TestGetHeader_OverrideInitialValues(t *testing.T) {
	request := setupRequest()
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	accept := "application/xml"
	acceptCharset := "utf16"
	acceptEncoding := "en-US"
	acceptLanguage := "en"
	addr := "192.168.1.1"
	proto := "grpc"
	header, err := c.buildHeader(request, &RequestMetadata{
		Accept:         &accept,
		AcceptCharset:  &acceptCharset,
		AcceptEncoding: &acceptEncoding,
		AcceptLanguage: &acceptLanguage,
		Addr:           &addr,
		Protocol:       &proto,
	})

	assert.Nil(t, err)

	// required fields
	assert.Equal(t, "application/xml", header.Accept)
	assert.Equal(t, "utf16", header.AcceptCharset)
	assert.Equal(t, "en-US", header.AcceptEncoding)
	assert.Equal(t, "en", header.AcceptLanguage)
	assert.Equal(t, "192.168.1.1", header.Addr)
	assert.Equal(t, "grpc", header.Protocol)
}

func TestGetModule(t *testing.T) {
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	module := c.getModule()
	assert.Equal(t, defaultModuleNameValue, module.Name)
	assert.Equal(t, defaultModuleVersionValue, module.Version)
	timeString := strconv.Itoa(int(module.RequestTimeMicros))
	assert.Len(t, timeString, 16)
}

type MockEvent struct {
	ValidateFunc func(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error)
	CollectFunc  func(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error)
}

func (m *MockEvent) Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(c, r, module, header)
	}
	return nil, errors.New("Validate function not implemented")
}

func (m *MockEvent) Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
	if m.CollectFunc != nil {
		return m.CollectFunc(c, r, module, header)
	}
	return nil, errors.New("Collect function not implemented")
}

func TestValidate(t *testing.T) {
	request := setupRequest()
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	mockEvent := &MockEvent{
		ValidateFunc: func(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
			return &ResponsePayload{
				SuccessResponsePayload: SuccessResponsePayload{
					Action: Allow,
				},
			}, nil
		},
	}

	resp, err := c.Validate(request, mockEvent)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, Allow, resp.Action)
}

func TestValidateWithRequestMetadata(t *testing.T) {
	request := setupRequest()
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	mockEvent := &MockEvent{
		ValidateFunc: func(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
			return &ResponsePayload{
				SuccessResponsePayload: SuccessResponsePayload{
					Action: Allow,
				},
			}, nil
		},
	}

	resp, err := c.ValidateWithRequestMetadata(request, mockEvent, nil)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, Allow, resp.Action)
}

func TestCollect(t *testing.T) {
	request := setupRequest()
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	mockEvent := &MockEvent{
		CollectFunc: func(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
			return nil, nil
		},
	}

	_, err = c.Collect(request, mockEvent)
	assert.Nil(t, err)
}

func TestCollectWithRequestMetadata(t *testing.T) {
	request := setupRequest()
	c, err := NewClient("your-fraud-api-key")

	assert.Nil(t, err)
	assert.NotNil(t, c)

	mockEvent := &MockEvent{
		CollectFunc: func(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
			return nil, nil
		},
	}

	_, err = c.CollectWithRequestMetadata(request, mockEvent, nil)
	assert.Nil(t, err)
}

func TestWithEndpoint(t *testing.T) {
	t.Run("Instantiate without protocol", func(t *testing.T) {
		endpoint := "api.example.org"
		client, err := NewClient(
			"your-api-key",
			ClientWithEndpoint(endpoint),
		)

		assert.NotNil(t, client)
		assert.Nil(t, err)
		assert.Equal(t, "https://api.example.org", client.Endpoint)
	})

	t.Run("Instantiate with HTTP protocol", func(t *testing.T) {
		endpoint := "http://api.example.org"
		client, err := NewClient(
			"your-api-key",
			ClientWithEndpoint(endpoint),
		)

		assert.NotNil(t, client)
		assert.Nil(t, err)
		assert.Equal(t, "http://api.example.org", client.Endpoint)
	})

	t.Run("Instantiate with HTTPS protocol", func(t *testing.T) {
		endpoint := "https://api.example.org"
		client, err := NewClient(
			"your-api-key",
			ClientWithEndpoint(endpoint),
		)

		assert.NotNil(t, client)
		assert.Nil(t, err)
		assert.Equal(t, "https://api.example.org", client.Endpoint)
	})
}

func TestWithTimeout(t *testing.T) {
	t.Run("With a positive integer", func(t *testing.T) {
		timeout := 1500
		client, err := NewClient(
			"your-api-key",
			ClientWithTimeout(timeout),
		)

		assert.NotNil(t, client)
		assert.Nil(t, err)
		assert.Equal(t, timeout, client.Timeout)
	})

	t.Run("With an integer less than or equal to 0", func(t *testing.T) {
		timeout := 0
		client, err := NewClient(
			"your-api-key",
			ClientWithTimeout(timeout),
		)

		assert.Nil(t, client)
		assert.NotNil(t, err)
		assert.Equal(t, ErrWrongTimeoutValue.Error(), err.Error())
	})
}

func ExampleClientWithEndpoint() {
	c, _ := NewClient("your-api-key", ClientWithEndpoint("account-api.example.org"))

	fmt.Println(c.Endpoint)
	// Output: https://account-api.example.org
}

func ExampleClientWithTimeout() {
	c, _ := NewClient("your-api-key", ClientWithTimeout(300))

	fmt.Println(c.Timeout)
	// Output: 300
}
