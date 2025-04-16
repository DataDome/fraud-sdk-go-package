package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// PasswordUpdateOption describes the functional option signature to customize the [PasswordUpdateEvent] behavior.
type PasswordUpdateOption func(*PasswordUpdateEvent)

// PasswordUpdateWithSession is a functional option to set the [Session] field.
func PasswordUpdateWithSession(session Session) PasswordUpdateOption {
	return func(e *PasswordUpdateEvent) {
		e.Session = &session
	}
}

// NewPasswordUpdateEvent instantiates a new [AccountUpdateEvent] that implements the [Event] interface.
func NewPasswordUpdateEvent(account string, user User, reason PasswordUpdateReason, status PasswordUpdateStatus, options ...PasswordUpdateOption) *PasswordUpdateEvent {
	event := &PasswordUpdateEvent{
		Account: account,
		Action:  PasswordUpdate,
		Reason:  reason,
		Session: nil,
		Status:  status,
		User:    user,
	}

	// apply functional options
	for _, opt := range options {
		opt(event)
	}

	return event
}

// Validate is used to construct the [PasswordUpdateRequestPayload] based on the information stored
// in the [PasswordUpdateEvent] structure and performs the validation request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *PasswordUpdateEvent) Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
	requestPayload := &PasswordUpdateRequestPayload{
		CommonRequestPayload: CommonRequestPayload{
			Account: e.Account,
			Header:  *header,
			Module:  *module,
		},
		Reason:  e.Reason,
		Session: e.Session,
		Status:  e.Status,
		User:    e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/validate/password/update", c.Endpoint)
	responseStatusCode, responsePayload, err := performRequest(r.Context(), c, endpoint, requestPayload)
	if err != nil {
		resp := &ResponsePayload{
			SuccessResponsePayload: SuccessResponsePayload{
				Action: Allow,
			},
		}
		if errors.Is(err, ErrRequestTimeout) {
			resp.Status = Timeout
		} else {
			resp.Status = Failure
		}
		return resp, fmt.Errorf("fail to validate password update request: %w", err)
	}
	if !(responseStatusCode >= 200 && responseStatusCode < 300) {
		return handleErrorResponse(responsePayload), nil
	}
	resp, err := decodeResponse[ResponsePayload](responsePayload)
	if err != nil {
		return &ResponsePayload{
			SuccessResponsePayload: SuccessResponsePayload{
				Action: Allow,
				Status: Failure,
			},
		}, err
	}
	resp.Status = OK
	return resp, nil
}

// Collect is used to construct the [PasswordUpdateRequestPayload] based on the information stored
// in the [PasswordUpdateEvent] structure and performs the enrichment request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *PasswordUpdateEvent) Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
	requestPayload := &PasswordUpdateRequestPayload{
		CommonRequestPayload: CommonRequestPayload{
			Account: e.Account,
			Header:  *header,
			Module:  *module,
		},
		Reason:  e.Reason,
		Session: e.Session,
		Status:  e.Status,
		User:    e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/collect/password/update", c.Endpoint)
	responseStatusCode, responsePayload, err := performRequest(r.Context(), c, endpoint, requestPayload)
	if err != nil {
		return nil, fmt.Errorf("fail to collect password update request: %w", err)
	}
	if !(responseStatusCode >= 200 && responseStatusCode < 300) {
		responsePayload := handleErrorResponse(responsePayload)
		return &responsePayload.ErrorResponsePayload, nil
	}
	return nil, nil
}
