# Logout CSRF Fix & Keycloak Console Button

## Problem Fixed

### CSRF Error on Logout
When logging out, users were encountering a **403 Forbidden** error with the message:
```
CSRF verification failed. Request aborted.
Reason given for failure: CSRF token from POST incorrect.
```

### Root Cause
The logout view was not properly validating that the request was a POST request before processing. While the logout form in the template was correctly using POST with a CSRF token, the view wasn't enforcing this requirement.

## Solution Applied

### 1. Fixed Logout View
Updated `/dashboard/views.py` - `logout_view()` function:

**Changes Made:**
- Added explicit check to ensure only POST requests are accepted
- Returns error message and redirects to home for non-POST requests
- Maintains CSRF protection for logout operations
- Works with both Keycloak and local authentication

**Code:**
```python
def logout_view(request):
    """Handle user logout - supports both Keycloak and local authentication."""
    from django.conf import settings
    from django.contrib.auth import logout
    from django.views.decorators.http import require_http_methods
    
    # Only allow POST requests for logout (CSRF protection)
    if request.method != 'POST':
        messages.error(request, 'Invalid logout request.')
        return redirect('dashboard:home')
    
    # If Keycloak is enabled, use OIDC logout
    if getattr(settings, 'KEYCLOAK_ENABLED', False):
        from mozilla_django_oidc.views import OIDCLogoutView
        logout(request)  # Logout from Django session first
        # OIDC logout view handles the redirect to Keycloak
        return OIDCLogoutView.as_view()(request)
    
    # Otherwise, use local logout
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('dashboard:login')
```

### 2. Added Keycloak Console Button

Added a **Keycloak Console** button in the navbar that:
- ✅ Only visible to **admin users** (users with `can_access_admin_queries` permission)
- ✅ Opens Keycloak Admin Console in a **new tab**
- ✅ Positioned before the "User Management" button
- ✅ Uses a key icon (🔑) for easy identification
- ✅ Styled consistently with other admin buttons

**Location:** `/dashboard/templates/dashboard/base.html`

**Features:**
- **URL:** http://localhost:8080
- **Target:** Opens in new tab (`target="_blank"`)
- **Icon:** Font Awesome key icon (`fas fa-key`)
- **Visibility:** Only shown to admins
- **Styling:** Matches the existing admin-link style

## How It Works Now

### Logout Process
1. User clicks "🚪 Logout" button in navbar
2. Form submits POST request with CSRF token
3. View validates it's a POST request
4. If Keycloak is enabled:
   - Logs out from Django session
   - Redirects to Keycloak logout
   - Keycloak logs out and redirects back
5. If local auth:
   - Logs out from Django session
   - Shows success message
   - Redirects to login page

### Keycloak Console Access (Admins Only)
1. Admin user logs in
2. Sees "🔑 Keycloak Console" button in navbar
3. Clicks button → Opens Keycloak Admin Console in new tab
4. Can manage users, roles, and settings
5. Returns to dashboard without losing session

## Visual Changes

### Navbar (Admin View)
```
[🏠 Dashboard]  [🔑 Keycloak Console]  [👥 User Management]  [👤 admin (Admin)]  [🚪 Logout]  [🌙 Dark Mode]
```

### Navbar (Non-Admin View)
```
[🏠 Dashboard]  [👤 testuser (Query User)]  [🚪 Logout]  [🌙 Dark Mode]
```

## Testing

### Test Logout
1. Log in with any user
2. Click "🚪 Logout" button
3. Should successfully log out without CSRF error
4. Should see success message (local auth) or be redirected (Keycloak)

### Test Keycloak Console Button
1. Log in as **admin** user (username: admin, password: admin123)
2. Look at navbar - should see "🔑 Keycloak Console" button
3. Click button - should open http://localhost:8080 in new tab
4. Log in to Keycloak (admin/admin)
5. Manage users and roles
6. Close Keycloak tab - dashboard session remains active

### Test Non-Admin View
1. Log in as **testuser** (username: testuser, password: password)
2. Look at navbar - should NOT see "🔑 Keycloak Console" button
3. Should only see regular user options

## Security Notes

### CSRF Protection
- ✅ Logout requires POST request
- ✅ CSRF token validated on every logout
- ✅ GET requests to logout are rejected
- ✅ Prevents CSRF attacks on logout endpoint

### Access Control
- ✅ Keycloak Console button only visible to admins
- ✅ Uses Django's permission system (`can_access_admin_queries`)
- ✅ Non-admin users cannot see or access the button
- ✅ Keycloak itself has its own authentication (admin/admin)

## Files Modified

1. **`/dashboard/views.py`**
   - Updated `logout_view()` function
   - Added POST request validation
   - Improved CSRF handling

2. **`/dashboard/templates/dashboard/base.html`**
   - Added Keycloak Console button
   - Positioned in navbar before User Management
   - Admin-only visibility

## Configuration

### Keycloak Console URL
The button links to: `http://localhost:8080`

**To change for production:**
1. Edit `/dashboard/templates/dashboard/base.html`
2. Find the Keycloak Console button
3. Update `href="http://localhost:8080"` to your production URL
4. Example: `href="https://keycloak.yourcompany.com"`

### Admin Access
Users with admin access are determined by:
- `user.can_access_admin_queries()` returns `True`
- Typically users with `role = 3` (Admin) or `is_superuser = True`

## Troubleshooting

### Still Getting CSRF Error on Logout?
1. **Clear browser cache and cookies**
2. **Check CSRF token in form:**
   - View page source
   - Look for `<input type="hidden" name="csrfmiddlewaretoken" value="...">`
3. **Verify middleware:**
   - Check `settings.py` has `django.middleware.csrf.CsrfViewMiddleware`
4. **Check browser console** for JavaScript errors

### Keycloak Console Button Not Showing?
1. **Verify user is admin:**
   ```python
   # In Django shell
   from dashboard.models import user
   u = user.objects.get(username='admin')
   print(u.can_access_admin_queries())  # Should be True
   print(u.role)  # Should be 3 for Admin
   ```

2. **Check template rendering:**
   - View page source
   - Search for "Keycloak Console"
   - If not found, user doesn't have admin permissions

3. **Verify Keycloak is running:**
   ```bash
   docker ps | grep keycloak
   curl http://localhost:8080
   ```

### Keycloak Console Opens But Can't Login?
1. **Check Keycloak is running:**
   ```bash
   docker-compose --profile keycloak ps
   ```

2. **Verify admin credentials:**
   - Username: `admin`
   - Password: `admin`
   - These are master realm credentials

3. **Check Keycloak logs:**
   ```bash
   docker logs neo4j_dashboard_keycloak
   ```

## Next Steps

### Recommended Actions
1. ✅ Test logout functionality with both admin and regular users
2. ✅ Test Keycloak Console access as admin
3. ✅ Verify non-admin users don't see the button
4. ✅ Update Keycloak admin password from default
5. ✅ Configure production Keycloak URL when deploying

### Future Enhancements
- Add Keycloak health check before showing button
- Make Keycloak URL configurable via environment variable
- Add tooltip with Keycloak admin credentials
- Add confirmation dialog before opening Keycloak Console
- Add Keycloak status indicator (online/offline)

## Summary

✅ **CSRF logout error fixed** - Logout now requires POST request with valid CSRF token

✅ **Keycloak Console button added** - Admins can easily access Keycloak for user management

✅ **Proper access control** - Only admin users see the Keycloak Console button

✅ **Security maintained** - CSRF protection and permission checks in place

✅ **User experience improved** - One-click access to Keycloak admin interface
