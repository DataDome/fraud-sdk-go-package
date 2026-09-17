package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CollectAccountUpdate is the operation struct for Post /v1/collect/account/update.
type CollectAccountUpdate struct {
	payload AccountUpdatePayload
}

// NewCollectAccountUpdate creates a new [CollectAccountUpdate] operation.
// Enrich DataDome engine
func NewCollectAccountUpdate(account string, opts ...AccountUpdatePayloadOption) (*CollectAccountUpdate, error) {
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
	return &CollectAccountUpdate{payload: payload}, nil
}

// PerformOperation executes the [CollectAccountUpdate] operation.
func (o *CollectAccountUpdate) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) error {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/collect/account/update", c.Endpoint)
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
