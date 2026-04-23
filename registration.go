package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// RegistrationEventOption describes the functional option signature to customize the [RegistrationEvent] behavior.
type RegistrationEventOption func(*RegistrationEvent)

// RegistrationWithAuthentication is a functional option to set the [Authentication] field.
func RegistrationWithAuthentication(authentication Authentication) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		e.Authentication = &authentication
	}
}

// RegistrationWithSession is a functional option to set the [Session] field.
func RegistrationWithSession(session Session) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		session.ID = truncatePointerValue(SessionIDField, session.ID)
		e.Session = &session
	}
}

// RegistrationWithStatus is a functional option to set the [RegistrationStatus] field.
func RegistrationWithStatus(status RegistrationStatus) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		e.Status = &status
	}
}

// RegistrationWithFailReason is a functional option to set the [RegistrationFailReason] field.
func RegistrationWithFailReason(reason RegistrationFailReason) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		e.FailReason = &reason
	}
}

// RegistrationWithAccountType is a functional option to set the [AccountType] field.
func RegistrationWithAccountType(accountType AccountType) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		e.AccountType = &accountType
	}
}

// RegistrationWithPartnerID is a functional option to set the partner ID field.
func RegistrationWithPartnerID(partnerID string) RegistrationEventOption {
	return func(e *RegistrationEvent) {
		truncated := truncateValue(PartnerIDField, partnerID)
		e.PartnerID = &truncated
	}
}

// RegistrationWithCustomFields is a functional option to set the custom fields.
func RegistrationWithCustomFields(fields []CustomField) RegistrationEventOption {
	return func(e *RegistrationEvent) {
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

// NewRegistrationEvent instantiates a new [RegistrationEvent] that implements the [Event] interface.
func NewRegistrationEvent(account string, user User, options ...RegistrationEventOption) *RegistrationEvent {
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

	event := &RegistrationEvent{
		CommonEvent: CommonEvent{
			Account: truncateValue(AccountField, account),
		},
		User: user,
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
		CommonRequestPayload: CommonRequestPayload{
			Account:        e.Account,
			Authentication: e.Authentication,
			CustomFields:   e.CustomFields,
			Header:         *header,
			Module:         *module,
			PartnerID:      e.PartnerID,
			Session:        e.Session,
		},
		AccountType: e.AccountType,
		FailReason:  e.FailReason,
		Status:      e.Status,
		User:        e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/validate/registration", c.Endpoint)
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
		CommonRequestPayload: CommonRequestPayload{
			Account:        e.Account,
			Authentication: e.Authentication,
			CustomFields:   e.CustomFields,
			Header:         *header,
			Module:         *module,
			PartnerID:      e.PartnerID,
			Session:        e.Session,
		},
		AccountType: e.AccountType,
		FailReason:  e.FailReason,
		Status:      e.Status,
		User:        e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/collect/registration", c.Endpoint)
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
