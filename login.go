package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// LoginOption describes the functional option signature to customize the [LoginEvent] behavior.
type LoginOption func(*LoginEvent)

// LoginWithUser is a functional option to set the [User] field.
func LoginWithUser(user User) LoginOption {
	return func(e *LoginEvent) {
		e.User = &user
	}
}

// LoginWithSession is a functional option to set the [Session] field.
func LoginWithSession(session Session) LoginOption {
	return func(e *LoginEvent) {
		e.Session = &session
	}
}

// LoginWithAuthentication is a functional option to set the [Authentication] field.
func LoginWithAuthentication(authentication Authentication) LoginOption {
	return func(e *LoginEvent) {
		e.Authentication = &authentication
	}
}

// NewLoginEvent instantiates a new [LoginEvent] that implements the [Event] interface.
func NewLoginEvent(account string, status LoginStatus, options ...LoginOption) *LoginEvent {
	event := &LoginEvent{
		Account: account,
		Action:  Login,
		Status:  status,
	}

	// apply functional options
	for _, opt := range options {
		opt(event)
	}

	return event
}

// Validate is used to construct the [LoginRequestPayload] based on the information stored in the [LoginEvent] structure
// and performs the validation request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *LoginEvent) Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
	requestPayload := &LoginRequestPayload{
		CommonRequestPayload: CommonRequestPayload{
			Account: e.Account,
			Header:  *header,
			Module:  *module,
		},
		Status:         e.Status,
		User:           e.User,
		Session:        e.Session,
		Authentication: e.Authentication,
	}
	endpoint := fmt.Sprintf("%s/v1/validate/login", c.Endpoint)
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
		return resp, fmt.Errorf("fail to validate login request: %w", err)
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

// Collect is used to construct the [LoginRequestPayload] based on the information stored in the [LoginEvent] structure
// and performs the enrichment request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *LoginEvent) Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
	requestPayload := &LoginRequestPayload{
		CommonRequestPayload: CommonRequestPayload{
			Account: e.Account,
			Header:  *header,
			Module:  *module,
		},
		Status:         e.Status,
		User:           e.User,
		Session:        e.Session,
		Authentication: e.Authentication,
	}
	endpoint := fmt.Sprintf("%s/v1/collect/login", c.Endpoint)
	responseStatusCode, responsePayload, err := performRequest(r.Context(), c, endpoint, requestPayload)
	if err != nil {
		return nil, fmt.Errorf("fail to collect login request: %w", err)
	}
	if !(responseStatusCode >= 200 && responseStatusCode < 300) {
		responsePayload := handleErrorResponse(responsePayload)
		return &responsePayload.ErrorResponsePayload, nil
	}
	return nil, nil
}
