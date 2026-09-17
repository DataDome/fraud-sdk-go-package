package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CollectPasswordUpdate is the operation struct for Post /v1/collect/password/update.
type CollectPasswordUpdate struct {
	payload PasswordUpdatePayload
}

// NewCollectPasswordUpdate creates a new [CollectPasswordUpdate] operation.
// Enrich DataDome engine
func NewCollectPasswordUpdate(account string, reason PasswordUpdatePayloadReason, status PasswordUpdatePayloadStatus, user PasswordUpdatePayloadAllOfUser, opts ...PasswordUpdatePayloadOption) (*CollectPasswordUpdate, error) {
	var payload PasswordUpdatePayload
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&payload)
	}
	if len(account) < 1 {
		return nil, fmt.Errorf("account: value must be at least 1 character(s)")
	}
	payload.Account = truncateValue(PasswordUpdatePayloadAccount, account)
	payload.Reason = reason
	payload.Status = status
	sanitizePasswordUpdatePayloadAllOfUser(&user)
	payload.User = user
	return &CollectPasswordUpdate{payload: payload}, nil
}

// PerformOperation executes the [CollectPasswordUpdate] operation.
func (o *CollectPasswordUpdate) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) error {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/collect/password/update", c.Endpoint)
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
