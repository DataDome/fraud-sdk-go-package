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
	"strconv"
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

// buildHeader is used to construct the [Header] type based on the incoming request.
// An error may be returned if the IP cannot be retrieved or if it failed to convert the port to an integer.
func (c *Client) buildHeader(r *http.Request) (*Header, error) {
	proto := getProtocol(r)

	ip, err := getIP(r)
	if err != nil {
		return nil, fmt.Errorf("fail to parse request's IP: %w", err)
	}

	stringPort := getPort(r)
	if stringPort == "" {
		if proto == "https" {
			stringPort = "443"
		} else {
			stringPort = "80"
		}
	}
	port, err := strconv.Atoi(stringPort)
	if err != nil {
		return nil, fmt.Errorf("error when converting port to an integer: %w", err)
	}

	return &Header{
		Accept:                 truncateValue(Accept, r.Header.Get("accept")),
		AcceptCharset:          truncateValue(AcceptCharset, r.Header.Get("accept-charset")),
		AcceptEncoding:         truncateValue(AcceptEncoding, r.Header.Get("accept-encoding")),
		AcceptLanguage:         truncateValue(AcceptLanguage, r.Header.Get("accept-language")),
		Addr:                   ip,
		ClientID:               truncateValue(ClientID, getClientId(r)),
		Connection:             truncateValue(Connection, r.Header.Get("connection")),
		ContentType:            truncateValue(ContentType, r.Header.Get("content-type")),
		From:                   truncateValue(From, r.Header.Get("from")),
		Host:                   truncateValue(Host, r.Host),
		Method:                 r.Method,
		Referer:                truncateValue(Referer, r.Header.Get("referer")),
		Request:                truncateValue(Request, getURL(r)),
		Origin:                 truncateValue(Origin, r.Header.Get("origin")),
		Port:                   port,
		Protocol:               proto,
		SecCHUA:                truncatePointerValue(SecCHUA, r.Header.Get("sec-ch-ua")),
		SecCHUAMobile:          truncatePointerValue(SecCHUAMobile, r.Header.Get("sec-ch-ua-mobile")),
		SecCHUAPlatform:        truncatePointerValue(SecCHUAPlatform, r.Header.Get("sec-ch-ua-platform")),
		SecCHUAArch:            truncatePointerValue(SecCHUAArch, r.Header.Get("sec-ch-ua-arch")),
		SecCHUAFullVersionList: truncatePointerValue(SecCHUAFullVersionList, r.Header.Get("sec-ch-ua-full-version-list")),
		SecCHUAModel:           truncatePointerValue(SecCHUAModel, r.Header.Get("sec-ch-ua-model")),
		SecCHDeviceMemory:      truncatePointerValue(SecCHDeviceMemory, r.Header.Get("sec-ch-device-memory")),
		ServerHostname:         truncateValue(ServerHostname, r.Host),
		UserAgent:              truncateValue(UserAgent, r.Header.Get("user-agent")),
		XForwardedForIP:        truncateValue(XForwardedForIP, r.Header.Get("x-forwarded-for")),
		XRealIP:                truncateValue(XRealIP, r.Header.Get("x-real-ip")),
	}, nil
}

// Validate performs a validation request to the DataDome's Account Protect API.
// This function extracts the information from the incoming request and returns the recommendation from the API.
// This function has to be called when the [Action] results with a success.
func (c *Client) Validate(r *http.Request, event Event) (*ResponsePayload, error) {
	header, err := c.buildHeader(r)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	module := c.getModule()

	return event.Validate(c, r, module, header)
}

// Collect performs an enrichment request to the DataDome's Account Protect API.
// This function extracts the information of the incoming request to enrich our detection models.
// This function has to be called when the [Action] results with a failure.
func (c *Client) Collect(r *http.Request, event Event) (*ErrorResponsePayload, error) {
	header, err := c.buildHeader(r)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	module := c.getModule()

	return event.Collect(c, r, module, header)
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
