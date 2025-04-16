package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// AccountUpdateOption describes the functional option signature to customize the [AccountUpdateEvent] behavior.
type AccountUpdateOption func(*AccountUpdateEvent)

// AccountUpdateWithSession is a functional option to set the [Session] field.
func AccountUpdateWithSession(session Session) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		e.Session = &session
	}
}

// AccountUpdateWithUser is a functional option to set the [User] field.
func AccountUpdateWithUser(user User) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		e.User = &user
	}
}

// NewAccountUpdateEvent instantiates a new [AccountUpdateEvent] that implements the [Event] interface.
func NewAccountUpdateEvent(account string, options ...AccountUpdateOption) *AccountUpdateEvent {
	event := &AccountUpdateEvent{
		Account: account,
		Action:  AccountUpdate,
		Session: nil,
		User:    nil,
	}

	// apply functional options
	for _, opt := range options {
		opt(event)
	}

	return event
}

// Validate is used to construct the [AccountUpdateRequestPayload] based on the information stored
// in the [NewAccountUpdateEvent] structure and performs the validation request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *AccountUpdateEvent) Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
	requestPayload := &AccountUpdateRequestPayload{
		CommonRequestPayload: CommonRequestPayload{
			Account: e.Account,
			Header:  *header,
			Module:  *module,
		},
		Session: e.Session,
		User:    e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/validate/account/update", c.Endpoint)
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
		return resp, fmt.Errorf("fail to validate account update request: %w", err)
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

// Collect is used to construct the [AccountUpdateRequestPayload] based on the information stored
// in the [AccountUpdateEvent] structure and performs the enrichment request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *AccountUpdateEvent) Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
	requestPayload := &AccountUpdateRequestPayload{
		CommonRequestPayload: CommonRequestPayload{
			Account: e.Account,
			Header:  *header,
			Module:  *module,
		},
		Session: e.Session,
		User:    e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/collect/account/update", c.Endpoint)
	responseStatusCode, responsePayload, err := performRequest(r.Context(), c, endpoint, requestPayload)
	if err != nil {
		return nil, fmt.Errorf("fail to collect account update request: %w", err)
	}
	if !(responseStatusCode >= 200 && responseStatusCode < 300) {
		responsePayload := handleErrorResponse(responsePayload)
		return &responsePayload.ErrorResponsePayload, nil
	}
	return nil, nil
}
