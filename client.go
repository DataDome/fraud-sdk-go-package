package fraudsdkgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ClientOption describes the functional option signature to customize the [Client] behavior.
type ClientOption func(*Client)

// ClientWithEndpoint is a functional option to set the endpoint of the Account Protect API.
func ClientWithEndpoint(endpoint string) ClientOption {
	return func(c *Client) {
		c.Endpoint = endpoint
	}
}

// ClientWithTimeout is a functional option to set the HTTP Client timeout in milliseconds.
func ClientWithTimeout(timeout int) ClientOption {
	return func(c *Client) {
		c.Timeout = timeout
	}
}

// NewClient instantiates a new DataDome [Client] to perform calls to the Account Protect API.
// The fields may be customized through [ClientOption] functions.
// It returns an error in case of bad inputs in the options.
func NewClient(fraudApiKey string, options ...ClientOption) (*Client, error) {
	c := &Client{
		Endpoint:      DefaultEndpointValue,
		FraudAPIKey:   fraudApiKey,
		Timeout:       DefaultTimeoutValue,
		moduleName:    defaultModuleNameValue,
		moduleVersion: defaultModuleVersionValue,
	}

	// apply functional options
	for _, opt := range options {
		opt(c)
	}

	// error management
	if c.FraudAPIKey == "" {
		return nil, ErrKeyMissing
	}
	if c.Timeout <= 0 {
		return nil, ErrWrongTimeoutValue
	}

	// set not exported values
	c.httpClient = &http.Client{
		Timeout: time.Millisecond * time.Duration(c.Timeout),
	}

	if !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		c.Endpoint = fmt.Sprintf("https://%s", c.Endpoint)
	}

	return c, nil
}

// getModule is used to construct the [Module] type based on the [Client] fields.
func (c *Client) getModule() *Module {
	return &Module{
		RequestTimeMicros: time.Now().UnixMicro(),
		Name:              c.moduleName,
		Version:           c.moduleVersion,
	}
}

// buildHeader is used to construct the [Header] type.
// It constructs this payload by reading the [RequestMetadata] fields if specified.
// It will extracts the information from the incoming request otherwise.
//
// An error may be returned if the IP cannot be retrieved.
func (c *Client) buildHeader(r *http.Request, rm *RequestMetadata) (*Header, error) {
	var proto string
	if rm.Protocol != nil {
		proto = *rm.Protocol
	} else {
		proto = getProtocol(r)
	}

	var ip string
	if rm.Addr != nil {
		ip = *rm.Addr
	} else {
		userIp, err := getIP(r)
		if err != nil {
			return nil, fmt.Errorf("fail to parse request's IP: %w", err)
		}
		ip = userIp
	}

	port := useMetadata(getPort(r), rm.Port)
	if port == -1 {
		if proto == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	return &Header{
		Accept:                 truncateValue(Accept, useMetadata(r.Header.Get("accept"), rm.Accept)),
		AcceptCharset:          truncateValue(AcceptCharset, useMetadata(r.Header.Get("accept-charset"), rm.AcceptCharset)),
		AcceptEncoding:         truncateValue(AcceptEncoding, useMetadata(r.Header.Get("accept-encoding"), rm.AcceptEncoding)),
		AcceptLanguage:         truncateValue(AcceptLanguage, useMetadata(r.Header.Get("accept-language"), rm.AcceptLanguage)),
		Addr:                   ip,
		ClientID:               truncateValue(ClientID, useMetadata(getClientId(r), rm.ClientID)),
		Connection:             truncateValue(Connection, useMetadata(r.Header.Get("connection"), rm.Connection)),
		ContentType:            truncateValue(ContentType, useMetadata(r.Header.Get("content-type"), rm.ContentType)),
		From:                   truncateValue(From, useMetadata(r.Header.Get("from"), rm.From)),
		Host:                   truncateValue(Host, useMetadata(r.Host, rm.Host)),
		Method:                 r.Method,
		Referer:                truncateValue(Referer, useMetadata(r.Header.Get("referer"), rm.Referer)),
		Request:                truncateValue(Request, useMetadata(getURL(r), rm.Request)),
		Origin:                 truncateValue(Origin, useMetadata(r.Header.Get("origin"), rm.Origin)),
		Port:                   port,
		Protocol:               proto,
		SecCHUA:                truncatePointerValue(SecCHUA, useMetadata(r.Header.Get("sec-ch-ua"), rm.SecCHUA)),
		SecCHUAMobile:          truncatePointerValue(SecCHUAMobile, useMetadata(r.Header.Get("sec-ch-ua-mobile"), rm.SecCHUAMobile)),
		SecCHUAPlatform:        truncatePointerValue(SecCHUAPlatform, useMetadata(r.Header.Get("sec-ch-ua-platform"), rm.SecCHUAPlatform)),
		SecCHUAArch:            truncatePointerValue(SecCHUAArch, useMetadata(r.Header.Get("sec-ch-ua-arch"), rm.SecCHUAArch)),
		SecCHUAFullVersionList: truncatePointerValue(SecCHUAFullVersionList, useMetadata(r.Header.Get("sec-ch-ua-full-version-list"), rm.SecCHUAFullVersionList)),
		SecCHUAModel:           truncatePointerValue(SecCHUAModel, useMetadata(r.Header.Get("sec-ch-ua-model"), rm.SecCHUAModel)),
		SecCHDeviceMemory:      truncatePointerValue(SecCHDeviceMemory, useMetadata(r.Header.Get("sec-ch-device-memory"), rm.SecCHDeviceMemory)),
		ServerHostname:         truncateValue(ServerHostname, useMetadata(r.Host, rm.ServerHostname)),
		UserAgent:              truncateValue(UserAgent, useMetadata(r.Header.Get("user-agent"), rm.UserAgent)),
		XForwardedForIP:        truncateValue(XForwardedForIP, useMetadata(r.Header.Get("x-forwarded-for"), rm.XForwardedForIP)),
		XRealIP:                truncateValue(XRealIP, useMetadata(r.Header.Get("x-real-ip"), rm.XRealIP)),
	}, nil
}

// validate is the internal function that performs the validation request to the Account Protect API.
func (c *Client) validate(r *http.Request, event Event, requestMetadata *RequestMetadata) (*ResponsePayload, error) {
	header, err := c.buildHeader(r, requestMetadata)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	module := c.getModule()

	return event.Validate(c, r, module, header)
}

// Validate performs a validation request to the DataDome's Account Protect API.
// This function extracts the information from the incoming request to construct the [Header] structure
// and returns the recommendation from the API.
func (c *Client) Validate(r *http.Request, event Event) (*ResponsePayload, error) {
	return c.validate(r, event, &RequestMetadata{})
}

// ValidateWithRequestMetadata performs a validation request to the DataDome's Account Protect API.
// This function is similar to the [Validate] function but allows the override of the [Header].
//
// If a field of the [RequestMetadata] structure is not specified, it will extracts the information
// from the incoming request.
func (c *Client) ValidateWithRequestMetadata(r *http.Request, event Event, requestMetadata *RequestMetadata) (*ResponsePayload, error) {
	if requestMetadata == nil {
		requestMetadata = &RequestMetadata{}
	}
	return c.validate(r, event, requestMetadata)
}

// collect is the internal function that performs the enrichment request to the Account Protect API.
func (c *Client) collect(r *http.Request, event Event, requestMetadata *RequestMetadata) (*ErrorResponsePayload, error) {
	header, err := c.buildHeader(r, requestMetadata)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	module := c.getModule()

	return event.Collect(c, r, module, header)
}

// Collect performs an enrichment request to the DataDome's Account Protect API.
// This function extracts the information of the incoming request to enrich our detection models.
func (c *Client) Collect(r *http.Request, event Event) (*ErrorResponsePayload, error) {
	return c.collect(r, event, &RequestMetadata{})
}

// CollectWithRequestMetadata performs an enrichment request to the DataDome's Account Protect API.
// This function is similar to the [Collect] function but allows the override of the [Header].
//
// If a field of the [RequestMetadata] structure is not specified, it will extracts the information
// from the incoming request.
func (c *Client) CollectWithRequestMetadata(r *http.Request, event Event, requestMetadata *RequestMetadata) (*ErrorResponsePayload, error) {
	if requestMetadata == nil {
		requestMetadata = &RequestMetadata{}
	}
	return c.collect(r, event, requestMetadata)
}

// performRequest performs the appropriate request to the DataDome's Account Protect API.
// This functions will:
// 1. Encode the provided payload that implements the [AllowedRequestPayload] interface.
// 2. Construct the request (i.e. attach the body, set the appropriate headers)
// 3. Performs the request to the Account Protect API.
// 4. Returns the response status code, the response body, and the potential error.
//
// An error may be returned in case of:
//   - an error when performing the request
//   - encoding/decoding the JSON payloads
//   - the request timeout (see [ErrRequestTimeout])
func performRequest[T AllowedRequestPayload](ctx context.Context, c *Client, endpoint string, payload *T) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return -1, nil, fmt.Errorf("fail to marshal request payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return -1, nil, fmt.Errorf("error when instancing new request: %w", err)
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-key", c.FraudAPIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return -1, nil, ErrRequestTimeout
		}
		return -1, nil, fmt.Errorf("error when performing HTTP request to the Account Protect API: %w", err)
	}
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, nil, fmt.Errorf("fail to read response body: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("error when closing the Body: %v\n", err)
		}
	}(resp.Body)
	return resp.StatusCode, responseBody, nil
}

// decodeResponse is used to decode a JSON-encoded response body to the specified type.
// It raises an error if it failed to unmarshal the response.
func decodeResponse[T any](response []byte) (*T, error) {
	var resp T
	err := json.Unmarshal(response, &resp)
	if err != nil {
		return nil, fmt.Errorf("fail to parse API's response: %w", err)
	}
	return &resp, nil
}

// handleErrorResponse is used to parse the JSON-encoded response body to the [ErrorResponsePayload] type.
// If an error is raised, it only returns the [Action] decision.
func handleErrorResponse(payload []byte) *ResponsePayload {
	responsePayload := &ResponsePayload{
		SuccessResponsePayload: SuccessResponsePayload{
			Action: Allow,
			Status: Failure,
		},
	}
	resp, err := decodeResponse[ErrorResponsePayload](payload)
	if err != nil {
		return responsePayload
	}
	responsePayload.ErrorResponsePayload = *resp
	return responsePayload
}
