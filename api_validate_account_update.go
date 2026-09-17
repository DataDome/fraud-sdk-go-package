package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ValidateAccountUpdate is the operation struct for Post /v1/validate/account/update.
type ValidateAccountUpdate struct {
	payload AccountUpdatePayload
}

// NewValidateAccountUpdate creates a new [ValidateAccountUpdate] operation.
// Validate if this account update event should be allowed, denied or reviewed.
func NewValidateAccountUpdate(account string, opts ...AccountUpdatePayloadOption) (*ValidateAccountUpdate, error) {
	var payload AccountUpdatePayload
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&payload)
	}
	if len(account) < 1 {
		return nil, fmt.Errorf("account: value must be at least 1 character(s)")
	}
	payload.Account = truncateValue(AccountUpdatePayloadAccount, account)
	return &ValidateAccountUpdate{payload: payload}, nil
}

// PerformOperation executes the [ValidateAccountUpdate] operation.
func (o *ValidateAccountUpdate) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) (*Response, error) {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/validate/account/update", c.Endpoint)
	result, err := post[Response](ctx, c, endpoint, &o.payload)
	if err != nil || result == nil {
		fallback := &Response{Action: ALLOW}
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
