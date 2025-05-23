# DataDome Fraud SDK Go

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
