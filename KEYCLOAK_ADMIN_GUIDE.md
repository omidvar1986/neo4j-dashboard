# Keycloak Admin Console Guide

## Accessing the Keycloak Admin Console

### 1. Open Keycloak Admin Console
- **URL:** http://localhost:8080
- **Admin Username:** `admin`
- **Admin Password:** `admin`

> **Note:** These are the **master realm** admin credentials, not the same as the users in your `neo4j_dashboard` realm.

### 2. Navigate to Your Realm
After logging in:
1. Click on the dropdown in the top-left corner (it will say "Master")
2. Select **`neo4j_dashboard`** from the list
3. You're now managing the `neo4j_dashboard` realm

---

## User Management

### Viewing Users
1. In the left sidebar, click **Users**
2. Click **View all users** button to see all users
3. You should see:
   - `admin` (admin@example.com)
   - `testuser` (test@example.com)

### Creating a New User
1. Click **Users** in the left sidebar
2. Click **Add user** button
3. Fill in the form:
   - **Username:** (required) - e.g., `john.doe`
   - **Email:** (optional) - e.g., `john@example.com`
   - **First name:** (optional) - e.g., `John`
   - **Last name:** (optional) - e.g., `Doe`
   - **Email verified:** Toggle ON if you want to skip email verification
   - **Enabled:** Toggle ON (users must be enabled to log in)
4. Click **Create**

### Setting User Password
After creating a user (or for existing users):
1. Click on the username to open user details
2. Go to the **Credentials** tab
3. Click **Set password**
4. Enter the password twice
5. Toggle **Temporary** OFF if you don't want the user to change password on first login
6. Click **Save**
7. Confirm by clicking **Save password**

### Editing User Details
1. Click **Users** → Select the user
2. In the **Details** tab, you can edit:
   - Email
   - First/Last name
   - Enable/Disable the user
3. Click **Save**

### Deleting a User
1. Click **Users** → Select the user
2. Click **Delete** button (top right)
3. Confirm the deletion

---

## Role Management

Keycloak has two types of roles:
- **Realm Roles:** Apply across the entire realm
- **Client Roles:** Specific to a client application (like `neo4j_dashboard_client`)

### Creating Realm Roles

1. Click **Realm roles** in the left sidebar
2. Click **Create role**
3. Fill in:
   - **Role name:** e.g., `admin`, `developer`, `viewer`
   - **Description:** (optional) Describe what this role does
4. Click **Save**

**Example Roles for Your Dashboard:**
- `admin` - Full administrative access
- `developer` - Can create and modify queries
- `analyst` - Can view and run queries
- `viewer` - Read-only access

### Creating Client Roles

1. Click **Clients** in the left sidebar
2. Click on **`neo4j_dashboard_client`**
3. Go to the **Roles** tab
4. Click **Create role**
5. Enter role name and description
6. Click **Save**

### Assigning Roles to Users

#### Method 1: From User Management
1. Click **Users** → Select a user
2. Go to the **Role mapping** tab
3. Click **Assign role**
4. You'll see two tabs:
   - **Filter by realm roles** - Shows realm-level roles
   - **Filter by clients** - Shows client-specific roles
5. Select the roles you want to assign
6. Click **Assign**

#### Method 2: From Role Management
1. Click **Realm roles** (or **Clients** → Your client → **Roles**)
2. Click on the role name
3. Go to the **Users in role** tab
4. Click **Add users**
5. Select users and click **Add**

### Viewing User's Roles
1. Click **Users** → Select a user
2. Go to the **Role mapping** tab
3. You'll see:
   - **Assigned roles** - Roles directly assigned to this user
   - **Effective roles** - All roles including inherited ones

---

## Group Management

Groups allow you to manage users collectively and assign roles to groups.

### Creating Groups
1. Click **Groups** in the left sidebar
2. Click **Create group**
3. Enter group name (e.g., `Administrators`, `Developers`)
4. Click **Create**

### Adding Users to Groups
1. Click **Users** → Select a user
2. Go to the **Groups** tab
3. Click **Join group**
4. Select the group(s)
5. Click **Join**

### Assigning Roles to Groups
1. Click **Groups** → Select a group
2. Go to the **Role mapping** tab
3. Click **Assign role**
4. Select roles and click **Assign**
5. All users in this group will inherit these roles

---

## Client Configuration

### Viewing Client Settings
1. Click **Clients** in the left sidebar
2. Click on **`neo4j_dashboard_client`**
3. Important tabs:
   - **Settings** - General client configuration
   - **Credentials** - Client secret (used in Django settings)
   - **Roles** - Client-specific roles
   - **Client scopes** - What information is shared with the client

### Important Client Settings
- **Client ID:** `neo4j_dashboard_client` (used in Django)
- **Client authentication:** ON (confidential client)
- **Valid redirect URIs:** 
  - `http://localhost:8000/oidc/callback/`
  - `http://127.0.0.1:8000/oidc/callback/`
- **Web origins:** 
  - `http://localhost:8000`
  - `http://127.0.0.1:8000`

### Getting Client Secret
1. Click **Clients** → **`neo4j_dashboard_client`**
2. Go to **Credentials** tab
3. Copy the **Client secret** value
4. This should match `KEYCLOAK_CLIENT_SECRET` in your Django settings

---

## Sessions Management

### Viewing Active Sessions
1. Click **Sessions** in the left sidebar
2. You'll see all active user sessions
3. You can revoke sessions if needed

### Viewing User Sessions
1. Click **Users** → Select a user
2. Go to the **Sessions** tab
3. See all active sessions for this user
4. Click **Sign out** to terminate sessions

---

## Realm Settings

### General Settings
1. Click **Realm settings** in the left sidebar
2. Important tabs:
   - **General** - Realm name, display settings
   - **Login** - Login page configuration
   - **Email** - Email server settings
   - **Themes** - Customize login page appearance
   - **Tokens** - Session timeout settings
   - **Security defenses** - Brute force detection, etc.

### Session Timeout Settings
1. **Realm settings** → **Tokens** tab
2. Configure:
   - **SSO Session Idle** - How long before idle session expires
   - **SSO Session Max** - Maximum session lifetime
   - **Access Token Lifespan** - How long access tokens are valid

---

## Authentication Settings

### Password Policies
1. Click **Authentication** in the left sidebar
2. Go to **Policies** tab
3. Click **Password policy** tab
4. Add policies like:
   - Minimum length
   - Require uppercase/lowercase
   - Require digits
   - Require special characters
   - Password history
   - Expire password after X days

### Required Actions
1. **Authentication** → **Required actions**
2. Configure actions users must complete:
   - Verify email
   - Update password
   - Update profile
   - Configure OTP

---

## Events and Logging

### Login Events
1. Click **Events** in the left sidebar
2. Go to **Login events** tab
3. See all login attempts (success and failures)
4. Useful for security monitoring

### Admin Events
1. **Events** → **Admin events** tab
2. See all administrative actions
3. Track who made what changes

### Enabling Event Logging
1. **Realm settings** → **Events** tab
2. **User events settings:**
   - Toggle **Save events** ON
   - Select event types to save
3. **Admin events settings:**
   - Toggle **Save events** ON
   - Toggle **Include representation** ON for detailed logs

---

## Common Administrative Tasks

### 1. Reset User Password
```
Users → Select user → Credentials → Set password
```

### 2. Disable User Account
```
Users → Select user → Details → Toggle "Enabled" OFF → Save
```

### 3. Make User an Admin
```
Users → Select user → Role mapping → Assign role → Select "admin" → Assign
```

### 4. View User Login History
```
Users → Select user → Sessions
```

### 5. Force User to Change Password
```
Users → Select user → Credentials → Set password → Toggle "Temporary" ON → Save
```

### 6. Check Why User Can't Login
```
Events → Login events → Filter by username → Check for errors
```

---

## Integration with Django

### How Roles Map to Django

When a user logs in via Keycloak:
1. Django receives user information from Keycloak
2. The user is auto-created in Django if they don't exist
3. User attributes are synced (email, first name, last name)
4. **Roles from Keycloak are NOT automatically mapped to Django roles**

### Current Setup

Your current Django integration:
- Creates users with default role (Query User)
- Users need approval (`is_approved=False` by default)
- Keycloak roles are available in the OIDC token but not automatically applied

### To Map Keycloak Roles to Django Roles

You would need to customize the OIDC backend in Django. Here's where to add this:

**File:** `dashboard/auth_backends.py` (create if doesn't exist)

```python
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

class CustomOIDCBackend(OIDCAuthenticationBackend):
    def create_user(self, claims):
        user = super().create_user(claims)
        self.update_user_roles(user, claims)
        return user
    
    def update_user(self, user, claims):
        user = super().update_user(user, claims)
        self.update_user_roles(user, claims)
        return user
    
    def update_user_roles(self, user, claims):
        # Get roles from Keycloak token
        roles = claims.get('groups', [])
        
        # Map Keycloak roles to Django roles
        if 'admin' in roles:
            user.role = 3  # Admin
            user.is_staff = True
            user.is_superuser = True
            user.is_approved = True
        elif 'developer' in roles:
            user.role = 2  # Developer
            user.is_approved = True
        elif 'analyst' in roles:
            user.role = 1  # Analyst
            user.is_approved = True
        else:
            user.role = 0  # Query User
            user.is_approved = False
        
        user.save()
```

Then update `settings.py`:
```python
AUTHENTICATION_BACKENDS = [
    'dashboard.auth_backends.CustomOIDCBackend',  # Custom OIDC backend
    'django.contrib.auth.backends.ModelBackend',  # Fallback
]
```

---

## Security Best Practices

### 1. Use Strong Passwords
- Enable password policies
- Require minimum 8 characters
- Require mix of uppercase, lowercase, numbers, symbols

### 2. Enable Brute Force Detection
```
Realm settings → Security defenses → Brute force detection → Toggle ON
```

### 3. Enable Email Verification
```
Authentication → Required actions → Enable "Verify Email"
```

### 4. Regular Session Timeout
```
Realm settings → Tokens → Set reasonable session timeouts
```

### 5. Monitor Login Events
```
Events → Login events → Check for suspicious activity
```

### 6. Use HTTPS in Production
- Never use HTTP for Keycloak in production
- Update redirect URIs to use HTTPS
- Configure SSL certificates

---

## Troubleshooting

### User Can't Login
1. Check if user is enabled: `Users → User → Details → Enabled`
2. Check password is set: `Users → User → Credentials`
3. Check login events: `Events → Login events`
4. Verify client configuration: `Clients → neo4j_dashboard_client`

### Roles Not Working
1. Verify role is assigned: `Users → User → Role mapping`
2. Check effective roles include the role
3. Verify client scopes include roles in token

### Session Issues
1. Check session timeout settings: `Realm settings → Tokens`
2. View active sessions: `Sessions`
3. Clear browser cookies and try again

---

## Quick Reference

### Admin Console Access
- **URL:** http://localhost:8080
- **Master Admin:** admin / admin
- **Realm:** neo4j_dashboard

### Current Users
| Username  | Password | Email              |
|-----------|----------|-------------------|
| admin     | admin123 | admin@example.com |
| testuser  | password | test@example.com  |

### Navigation Quick Links
- **Users:** Left sidebar → Users
- **Roles:** Left sidebar → Realm roles
- **Groups:** Left sidebar → Groups
- **Clients:** Left sidebar → Clients
- **Sessions:** Left sidebar → Sessions
- **Events:** Left sidebar → Events

---

## Next Steps

1. **Create Realm Roles:**
   - Create roles that match your Django roles (admin, developer, analyst, viewer)

2. **Assign Roles to Existing Users:**
   - Make `admin` user an admin role
   - Assign appropriate roles to `testuser`

3. **Set Up Password Policies:**
   - Configure password requirements for security

4. **Enable Event Logging:**
   - Track login attempts and admin actions

5. **Consider Custom Role Mapping:**
   - Implement the custom OIDC backend to automatically sync Keycloak roles to Django

6. **Production Preparation:**
   - Change default admin password
   - Configure HTTPS
   - Set up email server for notifications
   - Configure proper session timeouts

---

## Additional Resources

- **Official Documentation:** https://www.keycloak.org/documentation
- **Admin Console Guide:** https://www.keycloak.org/docs/latest/server_admin/
- **OIDC Integration:** https://www.keycloak.org/docs/latest/securing_apps/#_oidc
