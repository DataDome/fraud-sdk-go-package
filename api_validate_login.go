package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ValidateLogin is the operation struct for Post /v1/validate/login.
type ValidateLogin struct {
	payload LoginPayload
}

// NewValidateLogin creates a new [ValidateLogin] operation.
// Validate if this login event should be allowed, denied or reviewed.
func NewValidateLogin(account string, status LoginPayloadStatus, opts ...LoginPayloadOption) (*ValidateLogin, error) {
	var payload LoginPayload
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&payload)
	}
	if len(account) < 1 {
		return nil, fmt.Errorf("account: value must be at least 1 character(s)")
	}
	payload.Account = truncateValue(LoginPayloadAccount, account)
	payload.Status = status
	return &ValidateLogin{payload: payload}, nil
}

// PerformOperation executes the [ValidateLogin] operation.
func (o *ValidateLogin) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) (*ResponseLogin, error) {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/validate/login", c.Endpoint)
	result, err := post[ResponseLogin](ctx, c, endpoint, &o.payload)
	if err != nil || result == nil {
		fallback := &ResponseLogin{Action: ALLOW}
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			var apiErr Error
			if json.Unmarshal(httpErr.Body, &apiErr) == nil {
				fallback.Error = &apiErr
			}
		}
		return fallback, nil
	}
	return result, nil
}
