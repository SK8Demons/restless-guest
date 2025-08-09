"""
Configuration constants for the Azure Guest Access Management Tool.
"""

# Azure API endpoints
AZURE_LEGACY_RESOURCE = "https://management.core.windows.net/"
AZURE_RESOURCE = "https://management.azure.com"
GRAPH_RESOURCE = "https://graph.microsoft.com/"

# Application IDs
MAB_APP_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"  # MAB
AZURE_APP_ID = "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa"
OFFICE_365_MANAGEMENT_APP_ID = "00b41c95-dab0-4487-9791-b9d2c32c80f2"
AZURE_CLI_APP_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
POWERSHELL_APP_ID = "1950a258-227b-4e31-a9cf-717495945fc2"
POWER_BI_APP_ID = "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12"
IBIZA_UX_APP_ID = "74658136-14ec-4630-ad9b-26e160ff0fc6"
VS_CODE_APP_ID = "aebc6443-996d-45c2-90f0-388ff96faa56"


# API Versions
AZURE_API_VERSION = "2020-01-01"
BILLING_API_VERSION = "2020-11-01-privatepreview"
ROLE_ASSIGNMENTS_API_VERSION = "2020-04-01-preview"
SUBSCRIPTION_API_VERSION = "2021-10-01"
GRAPH_API_VERSION = "v1.0"
GRAPH_API_BETA_VERSION = "beta"
MANAGED_IDENTITY_API_VERSION = "2024-11-30"

# Common role definition IDs
OWNER_ROLE_ID = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_ID = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
READER_ROLE_ID = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"

# Default settings
DEFAULT_INVITE_REDIRECT_URL = "https://myapps.microsoft.com"
SEND_INVITATION_MESSAGE = False


# RBAC roles
OWNER_ROLE_ID="8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_ID="b24988ac-6180-42a0-ab88-20f7382dd24c"
VIRTUAL_MACHINE_USER_LOGIN_ROLE_ID="fb879df8-f326-4884-b1cf-06f3ad86be52"