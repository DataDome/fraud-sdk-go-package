package fraudsdkgo

import "errors"

var (
	ErrKeyMissing        = errors.New("fraudAPIKey must be defined")
	ErrRequestTimeout    = errors.New("request to Account Protect API timeout")
	ErrWrongTimeoutValue = errors.New("timeout must be a positive integer")
)
