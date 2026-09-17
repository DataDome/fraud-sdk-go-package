package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CollectLogin is the operation struct for Post /v1/collect/login.
type CollectLogin struct {
	payload LoginPayload
}

// NewCollectLogin creates a new [CollectLogin] operation.
// Enrich DataDome engine
func NewCollectLogin(account string, status LoginPayloadStatus, opts ...LoginPayloadOption) (*CollectLogin, error) {
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
	return &CollectLogin{payload: payload}, nil
}

// PerformOperation executes the [CollectLogin] operation.
func (o *CollectLogin) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) error {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/collect/login", c.Endpoint)
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
