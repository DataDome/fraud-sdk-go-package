package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CollectRegistration is the operation struct for Post /v1/collect/registration.
type CollectRegistration struct {
	payload RegistrationPayload
}

// NewCollectRegistration creates a new [CollectRegistration] operation.
// Enrich DataDome engine
func NewCollectRegistration(account string, user RegistrationPayloadAllOfUser, opts ...RegistrationPayloadOption) (*CollectRegistration, error) {
	var payload RegistrationPayload
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&payload)
	}
	if len(account) < 1 {
		return nil, fmt.Errorf("account: value must be at least 1 character(s)")
	}
	payload.Account = truncateValue(RegistrationPayloadAccount, account)
	sanitizeRegistrationPayloadAllOfUser(&user)
	payload.User = user
	return &CollectRegistration{payload: payload}, nil
}

// PerformOperation executes the [CollectRegistration] operation.
func (o *CollectRegistration) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) error {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/collect/registration", c.Endpoint)
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
