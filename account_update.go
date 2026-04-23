package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// AccountUpdateOption describes the functional option signature to customize the [AccountUpdateEvent] behavior.
type AccountUpdateOption func(*AccountUpdateEvent)

// AccountUpdateWithAuthentication is a functional option to set the [Authentication] field.
func AccountUpdateWithAuthentication(authentication Authentication) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		e.Authentication = &authentication
	}
}

// AccountUpdateWithSession is a functional option to set the [Session] field.
func AccountUpdateWithSession(session Session) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		session.ID = truncatePointerValue(SessionIDField, session.ID)
		e.Session = &session
	}
}

// AccountUpdateWithUser is a functional option to set the [User] field.
func AccountUpdateWithUser(user User) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
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

// AccountUpdateWithAccountType is a functional option to set the [AccountType] field.
func AccountUpdateWithAccountType(accountType AccountType) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		e.AccountType = &accountType
	}
}

// AccountUpdateWithAccountCreationDate is a functional option to set the account creation date field.
func AccountUpdateWithAccountCreationDate(date string) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		e.AccountCreationDate = &date
	}
}

// AccountUpdateWithPartnerID is a functional option to set the partner ID field.
func AccountUpdateWithPartnerID(partnerID string) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
		truncated := truncateValue(PartnerIDField, partnerID)
		e.PartnerID = &truncated
	}
}

// AccountUpdateWithCustomFields is a functional option to set the custom fields.
func AccountUpdateWithCustomFields(fields []CustomField) AccountUpdateOption {
	return func(e *AccountUpdateEvent) {
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

// NewAccountUpdateEvent instantiates a new [AccountUpdateEvent] that implements the [Event] interface.
func NewAccountUpdateEvent(account string, options ...AccountUpdateOption) *AccountUpdateEvent {
	event := &AccountUpdateEvent{
		CommonEvent: CommonEvent{
			Account: truncateValue(AccountField, account),
		},
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
		User:                e.User,
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
		User:                e.User,
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
