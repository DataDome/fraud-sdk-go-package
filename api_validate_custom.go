package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ValidateCustom is the operation struct for Post /v1/validate/custom.
type ValidateCustom struct {
	payload CustomActionPayload
}

// NewValidateCustom creates a new [ValidateCustom] operation.
// Validate if this custom event should be allowed, challenged, denied or reviewed.
func NewValidateCustom(eventName string, opts ...CustomActionPayloadOption) (*ValidateCustom, error) {
	var payload CustomActionPayload
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&payload)
	}
	if len(eventName) < 1 {
		return nil, fmt.Errorf("eventName: value must be at least 1 character(s)")
	}
	payload.EventName = truncateValue(CustomActionPayloadEventName, eventName)
	if payload.Account == nil && payload.User == nil {
		return nil, fmt.Errorf("at least one of account, user must be set")
	}
	return &ValidateCustom{payload: payload}, nil
}

// PerformOperation executes the [ValidateCustom] operation.
func (o *ValidateCustom) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) (*Response, error) {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/validate/custom", c.Endpoint)
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
