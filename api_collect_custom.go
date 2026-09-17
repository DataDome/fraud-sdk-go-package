package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CollectCustom is the operation struct for Post /v1/collect/custom.
type CollectCustom struct {
	payload CustomActionPayload
}

// NewCollectCustom creates a new [CollectCustom] operation.
// Enrich DataDome engine
func NewCollectCustom(eventName string, opts ...CustomActionPayloadOption) (*CollectCustom, error) {
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
	return &CollectCustom{payload: payload}, nil
}

// PerformOperation executes the [CollectCustom] operation.
func (o *CollectCustom) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) error {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/collect/custom", c.Endpoint)
	if postErr := postVoid(ctx, c, endpoint, &o.payload); postErr != nil {
		var httpErr *HTTPError
		if errors.As(postErr, &httpErr) {
			var apiErr Error
			if json.Unmarshal(httpErr.Body, &apiErr) == nil {
				return &apiErr
			}
		}
		return postErr
	}
	return nil
}
