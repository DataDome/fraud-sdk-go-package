# DataDome Fraud SDK Go

## v2.0.0 (2026-09-14)

### Breaking changes

- Refactor the SDK as a client generated from the Account Protect OpenAPI specification, replacing the previous hand-written implementation
- Update the module path from `github.com/datadome/fraud-sdk-go` to `github.com/datadome/fraud-sdk-go/v2`
- Update event submission to one dedicated struct per operation (e.g. `ValidateLogin`, `CollectCustom`, `Feedback`) instead of the `Event` interface and the `Client.Validate`/`Client.Collect` methods
- Update payload construction to functional options passed to per-operation constructors (e.g. `NewValidateLogin(account, status, opts...)`) instead of the previous per-event builders
- Update payload validation to run at construction time and fail on missing required fields instead of being silently accepted
- Update request execution to a `PerformOperation(ctx, client, request, requestMetadata)` method on each operation, now requiring an explicit `context.Context`, replacing `Validate`, `ValidateWithRequestMetadata`, `Collect`, and `CollectWithRequestMetadata`
- Update error handling so collect and feedback calls return a Go `error` (including the new `HTTPError` type and decoded API errors) instead of an `ErrorResponsePayload` with a `Status` field, while validate calls still fail open and return an `allow` action
- Rename `ResponsePayload`, `SuccessResponsePayload`, and `ErrorResponsePayload` to `Response`, `ResponseLogin`, and `Error`, remove the `Status` field, and uppercase the `ResponseAction` constants (`Allow` -> `ALLOW`, `Deny` -> `DENY`, `Review` -> `REVIEW`, `Challenge` -> `CHALLENGE`)
- Rename `LoginStatus` to `LoginPayloadStatus` and its `Failed`/`Succeeded` constants to `LoginPayloadStatusFailed`/`LoginPayloadStatusSucceeded`

### Other changes

- Add support for the feedback endpoint with `NewFeedback`

## v1.3.0 (2026-04-10)

- Add support for [custom events](https://docs.datadome.co/docs/account-protect-custom-events)
- Add optional `AccountCreationDate`, `PartnerID`, and `CustomFields` fields for every events
- Add optional `AccountType` field for login, registration, and account update events
- Add optional `FailReason` field for login and registration events
- Truncate fields of the events payload

## v1.2.1 (2025-06-23)

- Fix the case of the `XRealIP` in the JSON payload to the Account Protect API

## v1.2.0 (2025-06-12)

- Remove `Authentication` field from the `User` structure
- Add `AccountUpdateWithAuthentication` functional option to set the `Authentication` field for account update events
- Add `RegistrationWithAuthentication` functional option to set the `Authentication` field for registration events
- Add `PaymentMethodUpdated` field to the `User` structure for account update events

## v1.1.1 (2025-05-23)

- Fix the case of the `XForwardedForIP` in the JSON payload to the Account Protect API

## v1.1.0 (2025-04-16)

- Add support for [account update](https://docs.datadome.co/docs/account-protect-account-update) events
- Add support for [password update](https://docs.datadome.co/docs/account-protect-password-update) events
- Add optional `Session`, `User`, and `Authentication` fields for login events
- Add `Authentication`, `DisplayName`, `Description`, `ExternalURLs`, and `PictureURLs` fields to the `User` model
- Add the `Score` field on successful responses from the `Validate` method
- Add `ValidateWithRequestMetadata` and `CollectWithRequestMetadata` to allow overriding the initial request's metadata
- Fix the instantiation of the `Endpoint` field of the client when the protocol is provided

## v1.0.0 (2025-02-26)

- Initial release
