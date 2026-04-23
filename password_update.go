package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// PasswordUpdateOption describes the functional option signature to customize the [PasswordUpdateEvent] behavior.
type PasswordUpdateOption func(*PasswordUpdateEvent)

// RegistrationWithAuthentication is a functional option to set the [Authentication] field.
func PasswordUpdateWithAuthentication(authentication Authentication) PasswordUpdateOption {
	return func(e *PasswordUpdateEvent) {
		e.Authentication = &authentication
	}
}

// PasswordUpdateWithSession is a functional option to set the [Session] field.
func PasswordUpdateWithSession(session Session) PasswordUpdateOption {
	return func(e *PasswordUpdateEvent) {
		session.ID = truncatePointerValue(SessionIDField, session.ID)
		e.Session = &session
	}
}

// PasswordUpdateWithAccountCreationDate is a functional option to set the account creation date field.
func PasswordUpdateWithAccountCreationDate(date string) PasswordUpdateOption {
	return func(e *PasswordUpdateEvent) {
		e.AccountCreationDate = &date
	}
}

// PasswordUpdateWithPartnerID is a functional option to set the partner ID field.
func PasswordUpdateWithPartnerID(partnerID string) PasswordUpdateOption {
	return func(e *PasswordUpdateEvent) {
		truncated := truncateValue(PartnerIDField, partnerID)
		e.PartnerID = &truncated
	}
}

// PasswordUpdateWithCustomFields is a functional option to set the custom fields.
func PasswordUpdateWithCustomFields(fields []CustomField) PasswordUpdateOption {
	return func(e *PasswordUpdateEvent) {
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

// NewPasswordUpdateEvent instantiates a new [AccountUpdateEvent] that implements the [Event] interface.
func NewPasswordUpdateEvent(account string, user User, reason PasswordUpdateReason, status PasswordUpdateStatus, options ...PasswordUpdateOption) *PasswordUpdateEvent {
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

	event := &PasswordUpdateEvent{
		CommonEvent: CommonEvent{
			Account: truncateValue(AccountField, account),
		},
		Reason: reason,
		Status: status,
		User:   user,
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
			Account:        e.Account,
			Authentication: e.Authentication,
			CustomFields:   e.CustomFields,
			Header:         *header,
			Module:         *module,
			PartnerID:      e.PartnerID,
			Session:        e.Session,
		},
		AccountCreationDate: e.AccountCreationDate,
		Reason:              e.Reason,
		Status:              e.Status,
		User:                e.User,
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
			Account:        e.Account,
			Authentication: e.Authentication,
			CustomFields:   e.CustomFields,
			Header:         *header,
			Module:         *module,
			PartnerID:      e.PartnerID,
			Session:        e.Session,
		},
		AccountCreationDate: e.AccountCreationDate,
		Reason:              e.Reason,
		Status:              e.Status,
		User:                e.User,
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
