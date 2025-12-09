# Keycloak Integration Setup Guide

This guide explains how to set up and use Keycloak authentication with the Neo4j Dashboard.

## Overview

The Django application supports two authentication modes:
1. **Local Authentication** (default): Uses Django's built-in authentication system
2. **Keycloak Authentication**: Uses Keycloak as an identity provider via OIDC

You can switch between these modes using the `KEYCLOAK_ENABLED` environment variable.

## Prerequisites

- Keycloak server (can be local or remote)
- A Keycloak realm configured
- A Keycloak client configured for OIDC

## Configuration

### 1. Environment Variables

Add the following variables to your `.env` file (see `KEYCLOAK_CONFIG.md` for all available options):

```bash
# Enable/disable Keycloak authentication
KEYCLOAK_ENABLED=True

# Keycloak Server Configuration
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_REALM=your-realm-name

# OIDC Client Configuration
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret

# Redirect URI (must match Keycloak client configuration)
KEYCLOAK_REDIRECT_URI=http://localhost:8000/oidc/callback/
```

### 2. Keycloak Setup

#### Create a Realm (if needed)
1. Log into Keycloak Admin Console
2. Create a new realm or use an existing one
3. Note the realm name for `KEYCLOAK_REALM`

#### Create an OIDC Client
1. In your realm, go to **Clients** → **Create**
2. Set **Client ID**: Use a descriptive name (e.g., `neo4j-dashboard`)
3. Set **Client Protocol**: `openid-connect`
4. Click **Save**

#### Configure Client Settings
1. **Access Type**: Select `confidential` (for client secret)
2. **Valid Redirect URIs**: Add your redirect URI:
   - `http://localhost:8000/oidc/callback/*` (for development)
   - `https://your-domain.com/oidc/callback/*` (for production)
3. **Web Origins**: Add your application URL:
   - `http://localhost:8000` (for development)
   - `https://your-domain.com` (for production)
4. Click **Save**

#### Get Client Secret
1. Go to the **Credentials** tab of your client
2. Copy the **Secret** value
3. Set this as `KEYCLOAK_CLIENT_SECRET` in your `.env` file

#### Configure User Mappers (Optional)
To ensure user information (email, name, etc.) is available in tokens:
1. Go to **Clients** → Your Client → **Mappers**
2. Ensure these mappers exist:
   - `username` → Maps to `preferred_username`
   - `email` → Maps to `email`
   - `firstName` → Maps to `given_name`
   - `lastName` → Maps to `family_name`

## Using Docker Compose (Development)

If you want to run Keycloak locally for development:

```bash
# Start Keycloak and its database
docker-compose --profile keycloak up -d keycloak keycloak-db

# Access Keycloak Admin Console
# URL: http://localhost:8080
# Username: admin
# Password: admin
```

**Note**: The Keycloak services use a `keycloak` profile, so they won't start by default. This keeps your regular development environment lightweight.

## Testing the Integration

1. **Set `KEYCLOAK_ENABLED=True`** in your `.env` file
2. **Restart your Django application**
3. **Navigate to the login page**: `http://localhost:8000/login/`
4. You should be redirected to Keycloak for authentication
5. After successful authentication, you'll be redirected back to the dashboard

## Switching Between Authentication Modes

To switch back to local authentication:
1. Set `KEYCLOAK_ENABLED=False` in your `.env` file
2. Restart your Django application
3. The login page will now use local authentication

## User Management

### Auto-Creation of Users

When `KEYCLOAK_AUTO_CREATE_USERS=True` (default), users authenticated via Keycloak will be automatically created in the Django database.

### Auto-Update of Users

When `KEYCLOAK_AUTO_UPDATE_USERS=True` (default), user information (email, name, etc.) will be updated from Keycloak on each login.

### User Approval

By default, users created from Keycloak will have `is_approved=False`. You can:
- Manually approve users through the Django admin
- Modify the OIDC callback to auto-approve Keycloak users (see `dashboard/views.py`)

## Troubleshooting

### Common Issues

1. **"Invalid redirect URI"**
   - Ensure `KEYCLOAK_REDIRECT_URI` matches exactly what's configured in Keycloak
   - Check that the redirect URI is in the "Valid Redirect URIs" list

2. **"Client authentication failed"**
   - Verify `KEYCLOAK_CLIENT_SECRET` matches the secret in Keycloak
   - Ensure the client access type is set to "confidential"

3. **"User not found"**
   - Check that `OIDC_CREATE_USER=True` if you want automatic user creation
   - Verify the username claim mapping in settings

4. **"Connection refused"**
   - Ensure Keycloak server is running and accessible
   - Check `KEYCLOAK_SERVER_URL` is correct
   - If using Docker, ensure Keycloak container is running

### Debug Mode

Enable Django debug logging to see OIDC authentication flow:

```python
# In settings.py, add to LOGGING['loggers']:
'mozilla_django_oidc': {
    'handlers': ['console', 'file'],
    'level': 'DEBUG',
},
```

## Production Considerations

1. **Use HTTPS**: Always use HTTPS in production for OIDC
2. **Secure Secrets**: Store `KEYCLOAK_CLIENT_SECRET` securely (use secrets management)
3. **Session Security**: Configure secure session cookies
4. **Token Validation**: Ensure `OIDC_VERIFY_KID=True` (default)
5. **Keycloak High Availability**: Use a load-balanced Keycloak setup for production

## Additional Resources

- [Mozilla Django OIDC Documentation](https://mozilla-django-oidc.readthedocs.io/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)

