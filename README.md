# Application signing using GitHub actions

This repository is companion to 4D Method (4D user group)  [Advanced Application Signing](https://4dmethod.com/2026/01/09/advanced-application-signing-milan-adamov/) presentation.

Github actions presented here use standard macOS commands to sign application, create dmg image and to notarize dmg file. It uses official [Microsoft Azure Trusted Signing action](https://github.com/Azure/trusted-signing-action) to sign Windows application.

## Setup secrets

You need to setup your own secrets in order to sign applications on macOS and using Azure Trusted Signing.

