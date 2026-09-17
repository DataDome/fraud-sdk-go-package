package fraudsdkgo

import (
	"errors"
	"fmt"
)

var (
	ErrKeyMissing        = errors.New("fraudAPIKey must be defined")
	ErrRequestTimeout    = errors.New("request to Account Protect API timeout")
	ErrWrongTimeoutValue = errors.New("timeout must be a positive integer")
)

// HTTPError is returned when the Account Protect API responds with a non-2xx status code.
// Use errors.As to retrieve it and inspect StatusCode and Body when the error type cannot be determined.
type HTTPError struct {
	StatusCode int
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Account Protect API error (status %d): %s", e.StatusCode, string(e.Body))
}
