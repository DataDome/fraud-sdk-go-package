package fraudsdkgo

import (
	"errors"
	"fmt"
	"net/http"
)

// CustomEventOption describes the functional option signature to customize the [CustomEvent] behavior.
type CustomEventOption func(*CustomEvent)

// CustomEventWithEventStatus is a functional option to set the [CustomEventStatus] field.
func CustomEventWithEventStatus(status CustomEventStatus) CustomEventOption {
	return func(e *CustomEvent) {
		e.EventStatus = &status
	}
}

// CustomEventWithIsEventCritical is a functional option to set the IsEventCritical field.
func CustomEventWithIsEventCritical(critical bool) CustomEventOption {
	return func(e *CustomEvent) {
		e.IsEventCritical = &critical
	}
}

// CustomEventWithContent is a functional option to set the Content field.
func CustomEventWithContent(content string) CustomEventOption {
	return func(e *CustomEvent) {
		truncated := truncateValue(ContentField, content)
		e.Content = &truncated
	}
}

// CustomEventWithAccountTarget is a functional option to set the AccountTarget field.
func CustomEventWithAccountTarget(target string) CustomEventOption {
	return func(e *CustomEvent) {
		truncated := truncateValue(AccountTargetField, target)
		e.AccountTarget = &truncated
	}
}

// CustomEventWithSession is a functional option to set the [Session] field.
func CustomEventWithSession(session Session) CustomEventOption {
	return func(e *CustomEvent) {
		session.ID = truncatePointerValue(SessionIDField, session.ID)
		e.Session = &session
	}
}

// CustomEventWithAccountType is a functional option to set the [AccountType] field.
func CustomEventWithAccountType(accountType AccountType) CustomEventOption {
	return func(e *CustomEvent) {
		e.AccountType = &accountType
	}
}

// CustomEventWithAccountCreationDate is a functional option to set the account creation date field.
func CustomEventWithAccountCreationDate(date string) CustomEventOption {
	return func(e *CustomEvent) {
		e.AccountCreationDate = &date
	}
}

// CustomEventWithUser is a functional option to set the [CustomEventUser] field.
func CustomEventWithUser(user CustomEventUser) CustomEventOption {
	return func(e *CustomEvent) {
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

// CustomEventWithAuthentication is a functional option to set the [Authentication] field.
func CustomEventWithAuthentication(authentication Authentication) CustomEventOption {
	return func(e *CustomEvent) {
		e.Authentication = &authentication
	}
}

// CustomEventWithPartnerID is a functional option to set the partner ID field.
func CustomEventWithPartnerID(partnerID string) CustomEventOption {
	return func(e *CustomEvent) {
		truncated := truncateValue(PartnerIDField, partnerID)
		e.PartnerID = &truncated
	}
}

// CustomEventWithCustomFields is a functional option to set the custom fields.
func CustomEventWithCustomFields(fields []CustomField) CustomEventOption {
	return func(e *CustomEvent) {
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

// NewCustomEvent instantiates a new [CustomEvent] that implements the [Event] interface.
// account is the user account identifier; eventName must be camelCase (max 20 characters).
// Either account or a user with an ID must be set.
func NewCustomEvent(account string, eventName string, options ...CustomEventOption) *CustomEvent {
	event := &CustomEvent{
		CommonEvent: CommonEvent{
			Account: truncateValue(AccountField, account),
		},
		EventName: truncateValue(EventNameField, eventName),
	}

	// apply functional options
	for _, opt := range options {
		opt(event)
	}

	return event
}

// Validate is used to construct the [CustomEventRequestPayload] based on the information stored in the [CustomEvent]
// structure and performs the validation request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *CustomEvent) Validate(c *Client, r *http.Request, module *Module, header *Header) (*ResponsePayload, error) {
	requestPayload := &CustomEventRequestPayload{
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
		AccountTarget:       e.AccountTarget,
		AccountType:         e.AccountType,
		Content:             e.Content,
		EventName:           e.EventName,
		EventStatus:         e.EventStatus,
		IsEventCritical:     e.IsEventCritical,
		User:                e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/validate/custom", c.Endpoint)
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
		return resp, fmt.Errorf("fail to validate custom event request: %w", err)
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

// Collect is used to construct the [CustomEventRequestPayload] based on the information stored in the [CustomEvent]
// structure and performs the enrichment request to the Account Protect API.
// An error may be returned in case of error when performing the request.
func (e *CustomEvent) Collect(c *Client, r *http.Request, module *Module, header *Header) (*ErrorResponsePayload, error) {
	requestPayload := &CustomEventRequestPayload{
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
		AccountTarget:       e.AccountTarget,
		AccountType:         e.AccountType,
		Content:             e.Content,
		EventName:           e.EventName,
		EventStatus:         e.EventStatus,
		IsEventCritical:     e.IsEventCritical,
		User:                e.User,
	}
	endpoint := fmt.Sprintf("%s/v1/collect/custom", c.Endpoint)
	responseStatusCode, responsePayload, err := performRequest(r.Context(), c, endpoint, requestPayload)
	if err != nil {
		return nil, fmt.Errorf("fail to collect custom event request: %w", err)
	}
	if !(responseStatusCode >= 200 && responseStatusCode < 300) {
		responsePayload := handleErrorResponse(responsePayload)
		return &responsePayload.ErrorResponsePayload, nil
	}
	return nil, nil
}
