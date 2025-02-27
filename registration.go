package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// RegistrationEventOption describes the functional option signature to customize the [RegistrationEvent] behavior.
type RegistrationEventOption func(*RegistrationEvent)

// RegistrationWithSession is a functional option to set the [Session] field.
func RegistrationWithSession(session Session) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		e.Session = &session
	}
}

// NewRegistrationEvent instantiates a new [RegistrationEvent] that implements the [Event] interface.
func NewRegistrationEvent(account string, user User, options ...RegistrationEventOption) *RegistrationEvent {
	event := &RegistrationEvent{
		Account: account,
		Action:  Registration,
		Session: nil,
		User:    user,
	}

	// apply functional options
	for _, opt := range options {
		opt(event)
	}

	return event
}

// Validate is used to construct the [RegistrationRequestPayload] based on the information stored
// in the [RegistrationEvent] structure and performs the validation request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *RegistrationEvent) Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
	requestPayload := &RegistrationRequestPayload{
		Account: e.Account,
		Header:  *header,
		Module:  *module,
		Session: e.Session,
		User:    e.User,
	}
	endpoint := fmt.Sprintf("https://%s/v1/validate/registration", c.Endpoint)
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
		return resp, fmt.Errorf("fail to validate registration request: %w", err)
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

// Collect is used to construct the [RegistrationRequestPayload] based on the information stored
// in the [RegistrationEvent] structure and performs the enrichment request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *RegistrationEvent) Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
	requestPayload := &RegistrationRequestPayload{
		Account: e.Account,
		Header:  *header,
		Module:  *module,
		Session: e.Session,
		User:    e.User,
	}
	endpoint := fmt.Sprintf("https://%s/v1/collect/registration", c.Endpoint)
	responseStatusCode, responsePayload, err := performRequest(r.Context(), c, endpoint, requestPayload)
	if err != nil {
		return nil, fmt.Errorf("fail to collect registration request: %w", err)
	}
	if !(responseStatusCode >= 200 && responseStatusCode < 300) {
		responsePayload := handleErrorResponse(responsePayload)
		return &responsePayload.ErrorResponsePayload, nil
	}
	return nil, nil
}
