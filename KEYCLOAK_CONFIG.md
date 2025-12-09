# Keycloak Configuration Guide

This document describes the environment variables needed for Keycloak integration.

## Environment Variables

Add these variables to your `.env` file:

```bash
# Keycloak/OIDC Settings
# Set to True to enable Keycloak authentication, False to use local authentication
KEYCLOAK_ENABLED=False

# Keycloak Server URL (e.g., http://localhost:8080 or https://keycloak.example.com)
KEYCLOAK_SERVER_URL=http://localhost:8080

# Keycloak Realm Name
KEYCLOAK_REALM=your-realm-name

# OIDC Client ID (configured in Keycloak)
KEYCLOAK_CLIENT_ID=your-client-id

# OIDC Client Secret (configured in Keycloak)
KEYCLOAK_CLIENT_SECRET=your-client-secret

# OIDC Redirect URI (where Keycloak redirects after authentication)
# Default: http://localhost:8000/oidc/callback/
KEYCLOAK_REDIRECT_URI=http://localhost:8000/oidc/callback/

# OIDC Scope (default: openid profile email)
KEYCLOAK_SCOPE=openid profile email

# OIDC Username Claim (which claim from the token to use as username)
# Common values: preferred_username, email, sub
KEYCLOAK_USERNAME_CLAIM=preferred_username

# OIDC Email Claim (which claim from the token to use as email)
KEYCLOAK_EMAIL_CLAIM=email

# OIDC First Name Claim (which claim from the token to use as first name)
KEYCLOAK_FIRST_NAME_CLAIM=given_name

# OIDC Last Name Claim (which claim from the token to use as last name)
KEYCLOAK_LAST_NAME_CLAIM=family_name

# OIDC Groups/Roles Claim (which claim contains user groups/roles)
KEYCLOAK_GROUPS_CLAIM=groups

# Auto-create users from Keycloak (True/False)
KEYCLOAK_AUTO_CREATE_USERS=True

# Auto-update user information from Keycloak on each login (True/False)
KEYCLOAK_AUTO_UPDATE_USERS=True

# Session timeout in seconds (default: 3600 = 1 hour)
KEYCLOAK_SESSION_TIMEOUT=3600
```

## Keycloak Setup

1. **Create a Realm** in Keycloak (or use an existing one)
2. **Create a Client**:
   - Client ID: Use the value you set in `KEYCLOAK_CLIENT_ID`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential` (for client secret)
   - Valid Redirect URIs: Add your `KEYCLOAK_REDIRECT_URI`
   - Web Origins: Add your Django application URL
3. **Configure Client Secret**: Copy the secret and set it in `KEYCLOAK_CLIENT_SECRET`
4. **Configure User Mappers** (optional): Ensure the claims you need (email, given_name, family_name, etc.) are available in the token

## Usage

- When `KEYCLOAK_ENABLED=True`: Users will be redirected to Keycloak for authentication
- When `KEYCLOAK_ENABLED=False`: Users can use the local Django authentication system

