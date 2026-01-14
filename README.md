# Application signing using GitHub actions

This repository is companion to 4D Method (4D user group)  [Advanced Application Signing](https://4dmethod.com/2026/01/09/advanced-application-signing-milan-adamov/) presentation.

Github actions presented here use standard macOS commands to sign application, create dmg image and to notarize dmg file. It uses official [Microsoft Azure Trusted Signing action](https://github.com/Azure/trusted-signing-action) to sign Windows application.

## Setup secrets

You need to setup your own secrets in order to sign applications on macOS and using Azure Trusted Signing. 



| Secret name                    | Description                                                  |
| ------------------------------ | ------------------------------------------------------------ |
| APPLE_CERTIFICATE              | Base64 encoded .p12 file you saved from https://developer.apple.com/account/resources/certificates |
| APPLE_CERTIFICATE_NAME         | Name of certificate as displayed in Keychain                 |
| APPLE_CERTIFICATE_PASSWORD     | Certificate password, should be the password for MY_APPLE_ID developer account |
| MY_APPLE_ID                    | Apple developer account                                      |
| MY_TEAM_ID                     | Team ID of Apple Developer ID                                |
| MY_APP_SPECIFIC_PASSWORD       | App specific password you defined at https://account.apple.com/account/manage |
| KEYCHAIN_PASSWORD              | Password of temporary keychain created in macOS runner       |
| AZURE_ACCOUNT_NAME             |                                                              |
| AZURE_CERTIFICATE_PROFILE_NAME |                                                              |
| AZURE_CLIENT_ID                |                                                              |
| AZURE_CLIENT_SECRET            |                                                              |
| AZURE_ENDPOINT                 |                                                              |
| AZURE_TENANT_ID                |                                                              |
