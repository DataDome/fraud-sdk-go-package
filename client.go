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

const (
	DefaultEndpointValue      string = "https://account-api.datadome.co"
	DefaultTimeoutValue       int    = 1500
	defaultModuleNameValue    string = "Fraud SDK Go"
	defaultModuleVersionValue string = "2.0.0"
)

// Client is used to interact with the DataDome's Account Protect API.
// This structure contains all the information specified through the [ClientOption]'s functions.
type Client struct {
	Endpoint    string
	FraudAPIKey string
	Timeout     int

	httpClient    *http.Client
	moduleName    string
	moduleVersion string
}

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

// doPost performs a POST request to the given endpoint with the provided payload.
// It marshals the payload to JSON, attaches the API key, and performs the request.
// Returns the raw response body and status code, or an error.
func doPost(ctx context.Context, c *Client, endpoint string, payload any) ([]byte, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("fail to marshal request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, 0, fmt.Errorf("error when instancing new request: %w", err)
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-key", c.FraudAPIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return nil, 0, ErrRequestTimeout
		}
		return nil, 0, fmt.Errorf("error when performing HTTP request to the Account Protect API: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("fail to read response body: %w", err)
	}

	return responseBody, resp.StatusCode, nil
}

// post performs a POST request to the given endpoint with the provided payload.
// It marshals the payload to JSON, attaches the API key, performs the request,
// and unmarshals the response into the generic type T.
// Returns nil if the response body is empty (e.g. 201/204 with no content).
func post[T any](ctx context.Context, c *Client, endpoint string, payload any) (*T, error) {
	responseBody, statusCode, err := doPost(ctx, c, endpoint, payload)
	if err != nil {
		return nil, err
	}

	if statusCode >= 400 {
		return nil, &HTTPError{StatusCode: statusCode, Body: responseBody}
	}

	if len(responseBody) == 0 {
		return nil, nil
	}

	var result T
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("fail to parse API's response: %w", err)
	}

	return &result, nil
}

// postVoid performs a POST request to the given endpoint with the provided payload,
// discarding the response body. Used for collect endpoints that return no JSON payload.
func postVoid(ctx context.Context, c *Client, endpoint string, payload any) error {
	responseBody, statusCode, err := doPost(ctx, c, endpoint, payload)
	if err != nil {
		return err
	}

	if statusCode >= 400 {
		return &HTTPError{StatusCode: statusCode, Body: responseBody}
	}

	return nil
}
