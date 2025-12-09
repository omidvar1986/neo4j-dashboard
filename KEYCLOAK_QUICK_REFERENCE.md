# Keycloak Quick Reference Card

## 🔐 Access Information

**Keycloak Admin Console:** http://localhost:8080

**Master Realm Admin:**
- Username: `admin`
- Password: `admin`

**Your Realm:** `neo4j_dashboard`

**Existing Users:**
| Username  | Password | Email              | Purpose    |
|-----------|----------|-------------------|------------|
| admin     | admin123 | admin@example.com | Admin user |
| testuser  | password | test@example.com  | Test user  |

---

## 📍 Where to Find Things

### Switch Realm
**Location:** Top-left corner dropdown (shows "Master" by default)
**Action:** Click dropdown → Select "neo4j_dashboard"

### User Management
**Location:** Left sidebar → **Users**
**Common Tasks:**
- View all users: Click "View all users"
- Add user: Click "Add user" button
- Edit user: Click on username → Edit details
- Set password: Select user → "Credentials" tab → "Set password"
- Assign roles: Select user → "Role mapping" tab → "Assign role"
- Disable user: Select user → "Details" tab → Toggle "Enabled" OFF

### Role Management
**Location:** Left sidebar → **Realm roles**
**Common Tasks:**
- Create role: Click "Create role"
- View role: Click on role name
- Assign to user: Role → "Users in role" tab → "Add users"
- Delete role: Select role → "Delete" button

### Client Configuration
**Location:** Left sidebar → **Clients**
**Common Tasks:**
- View client: Click on "neo4j_dashboard_client"
- Get client secret: Client → "Credentials" tab
- Edit redirect URIs: Client → "Settings" tab
- Manage client roles: Client → "Roles" tab

### Group Management
**Location:** Left sidebar → **Groups**
**Common Tasks:**
- Create group: Click "Create group"
- Add users to group: Users → Select user → "Groups" tab → "Join group"
- Assign roles to group: Groups → Select group → "Role mapping" tab

### Session Management
**Location:** Left sidebar → **Sessions**
**Common Tasks:**
- View all sessions: Click "Sessions"
- View user sessions: Users → Select user → "Sessions" tab
- Revoke session: Click "Sign out" button

### Event Logging
**Location:** Left sidebar → **Events**
**Tabs:**
- **Login events:** See all login attempts
- **Admin events:** See all admin actions

### Realm Settings
**Location:** Left sidebar → **Realm settings**
**Important Tabs:**
- **General:** Realm name and display settings
- **Login:** Login page configuration
- **Tokens:** Session timeout settings
- **Security defenses:** Brute force detection
- **Events:** Enable event logging

---

## 🎯 Common Tasks - Step by Step

### 1️⃣ Create a New User
```
1. Left sidebar → Users
2. Click "Add user"
3. Fill in: Username (required), Email, First/Last name
4. Toggle "Enabled" ON
5. Click "Create"
6. Go to "Credentials" tab
7. Click "Set password"
8. Enter password (twice)
9. Toggle "Temporary" OFF (if you don't want forced password change)
10. Click "Save" → Confirm
```

### 2️⃣ Assign a Role to a User
```
1. Left sidebar → Users
2. Click "View all users"
3. Click on the username
4. Go to "Role mapping" tab
5. Click "Assign role"
6. Select the role(s) you want
7. Click "Assign"
```

### 3️⃣ Create a New Role
```
1. Left sidebar → Realm roles
2. Click "Create role"
3. Enter Role name (e.g., "developer")
4. Enter Description (optional)
5. Click "Save"
```

### 4️⃣ Reset User Password
```
1. Left sidebar → Users
2. Click on the username
3. Go to "Credentials" tab
4. Click "Set password"
5. Enter new password (twice)
6. Toggle "Temporary" OFF (or ON if you want them to change it)
7. Click "Save" → Confirm
```

### 5️⃣ Disable a User Account
```
1. Left sidebar → Users
2. Click on the username
3. In "Details" tab, toggle "Enabled" OFF
4. Click "Save"
```

### 6️⃣ View Login History
```
1. Left sidebar → Events
2. Go to "Login events" tab
3. Filter by username if needed
4. See all login attempts (success/failure)
```

### 7️⃣ Get Client Secret
```
1. Left sidebar → Clients
2. Click on "neo4j_dashboard_client"
3. Go to "Credentials" tab
4. Copy the "Client secret" value
```

### 8️⃣ Create a Group and Assign Roles
```
1. Left sidebar → Groups
2. Click "Create group"
3. Enter group name
4. Click "Create"
5. Click on the group name
6. Go to "Role mapping" tab
7. Click "Assign role"
8. Select roles
9. Click "Assign"
```

### 9️⃣ Add User to Group
```
1. Left sidebar → Users
2. Click on username
3. Go to "Groups" tab
4. Click "Join group"
5. Select group(s)
6. Click "Join"
```

### 🔟 View Active Sessions
```
1. Left sidebar → Sessions
2. See all active sessions
3. Click "Sign out" to revoke a session
```

---

## 🔍 Troubleshooting Quick Checks

### User Can't Login?
```
✓ Check: Users → Username → Details → "Enabled" is ON
✓ Check: Users → Username → Credentials → Password is set
✓ Check: Events → Login events → Look for error messages
✓ Check: Clients → neo4j_dashboard_client → Settings → Valid redirect URIs
```

### Role Not Working?
```
✓ Check: Users → Username → Role mapping → Role is assigned
✓ Check: Users → Username → Role mapping → Check "Effective roles"
✓ Check: Realm roles → Role name → Verify role exists
```

### Session Expired Too Quickly?
```
✓ Check: Realm settings → Tokens → SSO Session Idle
✓ Check: Realm settings → Tokens → SSO Session Max
✓ Increase timeout values if needed
```

---

## 🎨 Recommended Role Structure

For your Neo4j Dashboard, consider creating these roles:

| Role Name  | Description                           | Permissions                    |
|------------|---------------------------------------|--------------------------------|
| admin      | Full administrative access            | All features, user management  |
| developer  | Can create and modify queries         | Create/edit/delete queries     |
| analyst    | Can view and run queries              | View/run queries, view results |
| viewer     | Read-only access                      | View queries and results only  |

**To create these:**
```
Left sidebar → Realm roles → Create role → Enter name → Save
```

**To assign:**
```
Users → Select user → Role mapping → Assign role → Select role → Assign
```

---

## 🔒 Security Checklist

### Initial Setup
- [ ] Change master realm admin password from default
- [ ] Create realm-specific admin users
- [ ] Enable password policies
- [ ] Enable brute force detection
- [ ] Enable event logging

### Password Policy
```
Authentication → Policies → Password policy
Recommended:
- Minimum length: 8
- Require uppercase
- Require lowercase  
- Require digits
- Require special characters
```

### Brute Force Detection
```
Realm settings → Security defenses → Brute force detection
Toggle ON and configure:
- Max login failures: 5
- Wait increment: 60 seconds
- Max wait: 900 seconds
```

### Event Logging
```
Realm settings → Events
- Save events: ON
- Select event types to log
- Admin events: ON
- Include representation: ON
```

---

## 📊 Monitoring

### Daily Checks
- Review login events for failed attempts
- Check active sessions
- Review admin events for unauthorized changes

### Weekly Checks
- Review user list for inactive accounts
- Check role assignments
- Review password policy compliance

### Monthly Checks
- Audit admin actions
- Review and update roles
- Clean up inactive users
- Review session timeout settings

---

## 🚀 Next Steps

1. **Switch to neo4j_dashboard realm**
   - Top-left dropdown → Select "neo4j_dashboard"

2. **Create roles for your application**
   - Realm roles → Create: admin, developer, analyst, viewer

3. **Assign roles to existing users**
   - Make "admin" user an admin
   - Assign appropriate role to "testuser"

4. **Set up password policy**
   - Authentication → Policies → Configure requirements

5. **Enable event logging**
   - Realm settings → Events → Turn on logging

6. **Test the setup**
   - Try logging in with different users
   - Check that roles are assigned correctly
   - Verify sessions are working

---

## 📚 Additional Resources

- **Full Admin Guide:** See `KEYCLOAK_ADMIN_GUIDE.md`
- **Setup Documentation:** See `KEYCLOAK_SETUP.md`
- **Integration Details:** See `KEYCLOAK_INTEGRATION_SUMMARY.md`
- **Official Docs:** https://www.keycloak.org/documentation

---

## 💡 Pro Tips

1. **Always work in the correct realm** - Check the top-left dropdown shows "neo4j_dashboard"
2. **Use groups for bulk role assignment** - Easier than assigning roles individually
3. **Enable event logging early** - Helps with troubleshooting
4. **Test with a non-admin user** - Verify permissions work correctly
5. **Document your role structure** - Keep track of what each role can do
6. **Regular backups** - Export realm configuration periodically
7. **Use descriptive role names** - Makes management easier
8. **Monitor failed logins** - Security indicator
9. **Set reasonable session timeouts** - Balance security and UX
10. **Keep Keycloak updated** - Security patches are important

---

**Need Help?** 
- Check the Events → Login events for error messages
- Review the full admin guide in `KEYCLOAK_ADMIN_GUIDE.md`
- Check Keycloak logs: `docker logs neo4j_dashboard_keycloak`
