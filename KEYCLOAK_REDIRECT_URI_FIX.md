# Keycloak Logout Redirect URI Fix

## Problem

When logging out, users received the error:
```
We are sorry...
Invalid redirect uri
```

## Root Cause

Keycloak was rejecting the post-logout redirect URI because it wasn't configured in the client's allowed redirect URIs. The client only had:
- `http://localhost:8000/oidc/callback/`
- `http://127.0.0.1:8000/oidc/callback/`

But the logout was trying to redirect to:
- `http://localhost:8000/login/`

Which wasn't in the allowed list.

## Solution

Added wildcard redirect URIs to the Keycloak client configuration to allow any path:
- `http://localhost:8000/*`
- `http://127.0.0.1:8000/*`

This allows the logout to redirect to `/login/` or any other path in the application.

## Commands Executed

```bash
# Authenticate with Keycloak
docker exec -i neo4j_dashboard_keycloak /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin

# Update client redirect URIs to include wildcards
docker exec -i neo4j_dashboard_keycloak /opt/keycloak/bin/kcadm.sh update clients/c270f967-f500-4d66-a3a0-88907ed7a72f -r neo4j_dashboard -s 'redirectUris=["http://localhost:8000/oidc/callback/","http://127.0.0.1:8000/oidc/callback/","http://localhost:8000/*","http://127.0.0.1:8000/*"]'
```

## Files Modified

1. **`setup_all.sh`** - Updated to include wildcard redirect URIs in future setups

## Testing

Try logging out now:
1. Go to http://localhost:8000
2. Log in with any user
3. Click "🚪 Logout"
4. Should successfully logout and redirect to login page
5. No "Invalid redirect uri" error

## Note About Appearance

No changes were made to the appearance/styling of the application. If you're seeing different styling, it might be due to:
- Browser cache - Try hard refresh (Ctrl+Shift+R or Cmd+Shift+R)
- Theme toggle - Check if Dark Mode was accidentally enabled
- Session state - Different user roles might see slightly different layouts

To reset appearance:
- Clear browser cache
- Check theme toggle button (🌙 Dark Mode / ☀️ Light Mode)
- Verify you're logged in as the expected user

## Current Configuration

**Allowed Redirect URIs:**
- `http://localhost:8000/oidc/callback/` - OIDC login callback
- `http://127.0.0.1:8000/oidc/callback/` - OIDC login callback (IP)
- `http://localhost:8000/*` - Any path (including logout redirect)
- `http://127.0.0.1:8000/*` - Any path (IP)

This configuration allows:
✅ Login via Keycloak
✅ Logout with redirect to login page
✅ Any other redirects within the application
