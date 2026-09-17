package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ValidateRegistration is the operation struct for Post /v1/validate/registration.
type ValidateRegistration struct {
	payload RegistrationPayload
}

// NewValidateRegistration creates a new [ValidateRegistration] operation.
// Validate if this registration event should be allowed, denied or reviewed.
func NewValidateRegistration(account string, user RegistrationPayloadAllOfUser, opts ...RegistrationPayloadOption) (*ValidateRegistration, error) {
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
	return &ValidateRegistration{payload: payload}, nil
}

// PerformOperation executes the [ValidateRegistration] operation.
func (o *ValidateRegistration) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) (*Response, error) {
	if rm == nil {
		rm = &RequestMetadata{}
	}
	header, err := buildHeader(r, rm)
	if err != nil {
		return nil, fmt.Errorf("fail to extract request fingerprint: %w", err)
	}
	o.payload.Header = *header
	o.payload.Module = *c.getModule()
	endpoint := fmt.Sprintf("%s/v1/validate/registration", c.Endpoint)
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
