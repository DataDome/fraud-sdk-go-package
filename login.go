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
		user.ID = truncateValue(UserIDField, user.ID)
		user.FirstName = truncatePointerValue(UserFirstNameField, user.FirstName)
		user.LastName = truncatePointerValue(UserLastNameField, user.LastName)
		user.Phone = truncatePointerValue(UserPhoneField, user.Phone)
		user.Email = truncatePointerValue(UserEmailField, user.Email)
		user.DisplayName = truncatePointerValue(UserDisplayNameField, user.DisplayName)
		user.Description = truncatePointerValue(UserDescriptionField, user.Description)
		user.PictureURLs = capAndTruncateURLs(user.PictureURLs)
		user.ExternalURLs = capAndTruncateURLs(user.ExternalURLs)
		if user.Address != nil {
			addr := user.Address
			truncatedAddr := Address{
				Name:        truncatePointerValue(AddressNameField, addr.Name),
				Line1:       truncatePointerValue(AddressLine1Field, addr.Line1),
				Line2:       truncatePointerValue(AddressLine2Field, addr.Line2),
				City:        truncatePointerValue(AddressCityField, addr.City),
				CountryCode: truncatePointerValue(AddressCountryCodeField, addr.CountryCode),
				RegionCode:  truncatePointerValue(AddressRegionCodeField, addr.RegionCode),
				ZipCode:     truncatePointerValue(AddressZipCodeField, addr.ZipCode),
			}
			user.Address = &truncatedAddr
		}
		e.User = &user
	}
}

// LoginWithSession is a functional option to set the [Session] field.
func LoginWithSession(session Session) LoginOption {
	return func(e *LoginEvent) {
		session.ID = truncatePointerValue(SessionIDField, session.ID)
		e.Session = &session
	}
}

// LoginWithAuthentication is a functional option to set the [Authentication] field.
func LoginWithAuthentication(authentication Authentication) LoginOption {
	return func(e *LoginEvent) {
		e.Authentication = &authentication
	}
}

// LoginWithFailReason is a functional option to set the [LoginFailReason] field.
func LoginWithFailReason(reason LoginFailReason) LoginOption {
	return func(e *LoginEvent) {
		e.FailReason = &reason
	}
}

// LoginWithAccountType is a functional option to set the [AccountType] field.
func LoginWithAccountType(accountType AccountType) LoginOption {
	return func(e *LoginEvent) {
		e.AccountType = &accountType
	}
}

// LoginWithAccountCreationDate is a functional option to set the account creation date field.
func LoginWithAccountCreationDate(date string) LoginOption {
	return func(e *LoginEvent) {
		e.AccountCreationDate = &date
	}
}

// LoginWithPartnerID is a functional option to set the partner ID field.
func LoginWithPartnerID(partnerID string) LoginOption {
	return func(e *LoginEvent) {
		truncated := truncateValue(PartnerIDField, partnerID)
		e.PartnerID = &truncated
	}
}

// LoginWithCustomFields is a functional option to set the custom fields.
func LoginWithCustomFields(fields []CustomField) LoginOption {
	return func(e *LoginEvent) {
		if len(fields) > MaxCustomFields {
			fields = fields[:MaxCustomFields]
		}
		truncatedFields := make([]CustomField, len(fields))
		for i, f := range fields {
			truncatedFields[i] = CustomField{
				Name:  truncateValue(CustomFieldNameField, f.Name),
				Value: truncateValue(CustomFieldValueField, f.Value),
				Type:  f.Type,
				IsPii: f.IsPii,
			}
		}
		e.CustomFields = truncatedFields
	}
}

// NewLoginEvent instantiates a new [LoginEvent] that implements the [Event] interface.
func NewLoginEvent(account string, status LoginStatus, options ...LoginOption) *LoginEvent {
	event := &LoginEvent{
		CommonEvent: CommonEvent{
			Account: truncateValue(AccountField, account),
		},
		Status: status,
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
			Account:        e.Account,
			Authentication: e.Authentication,
			CustomFields:   e.CustomFields,
			Header:         *header,
			Module:         *module,
			PartnerID:      e.PartnerID,
			Session:        e.Session,
		},
		AccountCreationDate: e.AccountCreationDate,
		AccountType:         e.AccountType,
		FailReason:          e.FailReason,
		Status:              e.Status,
		User:                e.User,
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
			Account:        e.Account,
			Authentication: e.Authentication,
			CustomFields:   e.CustomFields,
			Header:         *header,
			Module:         *module,
			PartnerID:      e.PartnerID,
			Session:        e.Session,
		},
		AccountCreationDate: e.AccountCreationDate,
		AccountType:         e.AccountType,
		FailReason:          e.FailReason,
		Status:              e.Status,
		User:                e.User,
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
