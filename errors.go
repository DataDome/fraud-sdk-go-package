package fraudsdkgo

import "errors"

var (
	ErrKeyMissing        = errors.New("FraudAPIKey must be defined")
	ErrRequestTimeout    = errors.New("request to Account Protect API timeout")
	ErrWrongTimeoutValue = errors.New("Timeout must be a positive integer")
)
