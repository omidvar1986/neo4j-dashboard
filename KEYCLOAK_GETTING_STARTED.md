# Keycloak Administration - Getting Started

## 📖 Overview

This guide will help you get started with managing users, roles, and other administrative tasks in Keycloak for your Neo4j Dashboard project.

---

## 🚀 Quick Start

### 1. Access Keycloak Admin Console

Open your browser and go to: **http://localhost:8080**

**Login Credentials:**
- Username: `admin`
- Password: `admin`

> ⚠️ **Important:** These are the **master realm** admin credentials, not the users in your application.

### 2. Switch to Your Realm

After logging in:
1. Look at the **top-left corner** of the screen
2. You'll see a dropdown that says **"Master"**
3. Click on it
4. Select **"neo4j_dashboard"** from the list

> 💡 **Tip:** Always make sure you're in the `neo4j_dashboard` realm when managing your application users!

---

## 📚 Documentation Available

I've created comprehensive documentation for you:

### 1. **KEYCLOAK_ADMIN_GUIDE.md** (Comprehensive Guide)
   - Complete walkthrough of all Keycloak features
   - Detailed explanations of every section
   - Integration with Django
   - Security best practices
   - Troubleshooting guide

### 2. **KEYCLOAK_QUICK_REFERENCE.md** (Quick Reference)
   - Fast lookup for common tasks
   - Step-by-step instructions
   - Checklists and tips
   - Recommended role structure

### 3. **KEYCLOAK_SETUP.md** (Initial Setup)
   - How Keycloak was configured
   - Client configuration details
   - Environment variables

### 4. **KEYCLOAK_INTEGRATION_SUMMARY.md** (Django Integration)
   - How Keycloak works with Django
   - Authentication flow
   - User synchronization

---

## 🎯 Most Common Tasks

### Task 1: View All Users

```
1. Make sure you're in the "neo4j_dashboard" realm (top-left dropdown)
2. Click "Users" in the left sidebar
3. Click "View all users" button
4. You'll see: admin, testuser
```

### Task 2: Create a New User

```
1. Users → Click "Add user"
2. Fill in:
   - Username: (required) e.g., "john.doe"
   - Email: e.g., "john@example.com"
   - First name: "John"
   - Last name: "Doe"
   - Toggle "Enabled" ON
3. Click "Create"
4. Go to "Credentials" tab
5. Click "Set password"
6. Enter password twice
7. Toggle "Temporary" OFF (so they don't have to change it)
8. Click "Save" → Confirm
```

### Task 3: Assign Roles to a User

```
1. Users → Click on the username
2. Go to "Role mapping" tab
3. Click "Assign role" button
4. Select the role(s) you want to assign
5. Click "Assign"
```

### Task 4: Create a New Role

```
1. Click "Realm roles" in the left sidebar
2. Click "Create role"
3. Enter:
   - Role name: e.g., "developer"
   - Description: e.g., "Can create and modify queries"
4. Click "Save"
```

### Task 5: Reset a User's Password

```
1. Users → Click on the username
2. Go to "Credentials" tab
3. Click "Set password"
4. Enter new password twice
5. Toggle "Temporary" OFF
6. Click "Save" → Confirm
```

---

## 🗺️ Navigation Map

Here's where to find everything in the Keycloak Admin Console:

### Left Sidebar Menu

| Menu Item      | What You Can Do                                    |
|----------------|---------------------------------------------------|
| **Users**      | View, create, edit, delete users                  |
| **Realm roles**| Create and manage roles                           |
| **Groups**     | Create groups and assign bulk roles               |
| **Clients**    | Configure OAuth/OIDC clients (like your Django app)|
| **Sessions**   | View and manage active user sessions              |
| **Events**     | View login history and admin actions              |
| **Realm settings** | Configure realm-wide settings                 |
| **Authentication** | Configure login policies and requirements     |

### Top Navigation

| Element              | Purpose                                    |
|---------------------|-------------------------------------------|
| **Realm dropdown**  | Switch between realms (top-left)          |
| **User menu**       | Admin user settings and logout (top-right)|

---

## 🎨 Recommended Setup for Your Dashboard

### Step 1: Create Roles

Create these roles to match your Django application:

```
Realm roles → Create role

Role 1: "admin"
- Description: "Full administrative access"

Role 2: "developer"  
- Description: "Can create and modify queries"

Role 3: "analyst"
- Description: "Can view and run queries"

Role 4: "viewer"
- Description: "Read-only access"
```

### Step 2: Assign Roles to Existing Users

```
Make "admin" user an administrator:
Users → admin → Role mapping → Assign role → Select "admin" → Assign

Assign test user a role:
Users → testuser → Role mapping → Assign role → Select "developer" → Assign
```

### Step 3: Enable Security Features

```
Enable Password Policy:
Authentication → Policies → Password policy
Add: Minimum length (8), Uppercase, Lowercase, Digits, Special chars

Enable Brute Force Detection:
Realm settings → Security defenses → Brute force detection → Toggle ON

Enable Event Logging:
Realm settings → Events → Save events → Toggle ON
```

---

## 🔍 Understanding the User Flow

### When a User Logs In via Keycloak:

1. **User clicks "Login" in your Django app**
   - Django redirects to Keycloak login page

2. **User enters credentials in Keycloak**
   - Keycloak validates username/password
   - Keycloak checks if user is enabled
   - Keycloak logs the login event

3. **Keycloak sends user info back to Django**
   - User profile (email, name, etc.)
   - Assigned roles (if configured)
   - Authentication token

4. **Django creates/updates the user**
   - Creates user in Django database if new
   - Updates user information if existing
   - Logs user into Django session

### Where Users Are Stored:

- **Keycloak Database:** User credentials, roles, profile
- **Django Database:** User records, app-specific data
- **Both systems need the user** for login to work

---

## 🔐 Current User Accounts

### Master Realm Admin (for Keycloak management)
- **Username:** admin
- **Password:** admin
- **Purpose:** Manage Keycloak itself
- **Realm:** master

### Application Users (for your Django app)
| Username  | Password | Email              | Realm           |
|-----------|----------|-------------------|-----------------|
| admin     | admin123 | admin@example.com | neo4j_dashboard |
| testuser  | password | test@example.com  | neo4j_dashboard |

---

## 🎓 Learning Path

### Beginner (Start Here)
1. ✅ Access Keycloak Admin Console
2. ✅ Switch to neo4j_dashboard realm
3. ✅ View existing users
4. ✅ Create a test user
5. ✅ Set user password
6. ✅ Test login with new user

### Intermediate
1. Create realm roles
2. Assign roles to users
3. Create groups
4. Add users to groups
5. Configure password policies
6. View login events

### Advanced
1. Configure client scopes
2. Set up role mappers
3. Customize login themes
4. Configure session timeouts
5. Set up email server
6. Export/import realm configuration

---

## 🆘 Troubleshooting

### Problem: Can't find the realm dropdown
**Solution:** Look at the very top-left corner, next to the Keycloak logo. It shows the current realm name.

### Problem: User can't login
**Check:**
1. User exists in Keycloak: Users → View all users
2. User is enabled: Users → Username → Details → "Enabled" is ON
3. Password is set: Users → Username → Credentials
4. Check login events: Events → Login events → Filter by username

### Problem: Changes not taking effect
**Solution:** 
1. Make sure you clicked "Save" after making changes
2. User may need to log out and log back in
3. Clear browser cache/cookies

### Problem: Can't see neo4j_dashboard realm
**Solution:**
1. Make sure you ran `setup_all.sh` which creates the realm
2. Check if realm exists: Master realm → Realm dropdown → Should show neo4j_dashboard
3. If missing, re-run the setup script

---

## 📊 Visual Guides

I've created visual guides to help you navigate Keycloak:

1. **Keycloak Navigation Guide** - Shows the main menu structure
2. **Role Assignment Guide** - Step-by-step visual for assigning roles

These images are displayed above and show you exactly where to click!

---

## 🔗 Quick Links

### Documentation Files
- `KEYCLOAK_ADMIN_GUIDE.md` - Full administration guide
- `KEYCLOAK_QUICK_REFERENCE.md` - Quick reference card
- `KEYCLOAK_SETUP.md` - Setup and configuration
- `KEYCLOAK_INTEGRATION_SUMMARY.md` - Django integration details
- `KEYCLOAK_USERS_FIX.md` - Recent fix for missing admin user

### Keycloak URLs
- **Admin Console:** http://localhost:8080
- **Realm:** neo4j_dashboard
- **Client ID:** neo4j_dashboard_client

### Docker Commands
```bash
# View Keycloak logs
docker logs neo4j_dashboard_keycloak

# Restart Keycloak
docker-compose --profile keycloak restart keycloak

# Stop Keycloak
docker-compose --profile keycloak stop keycloak

# Start Keycloak
docker-compose --profile keycloak up -d keycloak
```

---

## ✅ Next Steps

1. **Access Keycloak Admin Console**
   - Go to http://localhost:8080
   - Login with admin/admin
   - Switch to neo4j_dashboard realm

2. **Create Your Role Structure**
   - Realm roles → Create: admin, developer, analyst, viewer
   - Document what each role can do

3. **Assign Roles to Existing Users**
   - Give "admin" user the admin role
   - Give "testuser" an appropriate role

4. **Test the Setup**
   - Try logging into your Django app with both users
   - Verify roles work correctly

5. **Enable Security Features**
   - Set up password policy
   - Enable brute force detection
   - Enable event logging

6. **Read the Full Documentation**
   - Review `KEYCLOAK_ADMIN_GUIDE.md` for comprehensive details
   - Keep `KEYCLOAK_QUICK_REFERENCE.md` handy for quick lookups

---

## 💡 Pro Tips

1. **Always check you're in the right realm** - The realm dropdown is easy to miss!
2. **Save frequently** - Changes aren't applied until you click Save
3. **Use groups for multiple users** - Easier than assigning roles individually
4. **Enable event logging early** - Helps with troubleshooting later
5. **Test with non-admin users** - Verify permissions work as expected
6. **Document your role structure** - Keep notes on what each role means
7. **Regular backups** - Export realm configuration periodically

---

## 📞 Need More Help?

- **Full Guide:** Open `KEYCLOAK_ADMIN_GUIDE.md` for detailed explanations
- **Quick Reference:** Open `KEYCLOAK_QUICK_REFERENCE.md` for fast lookups
- **Check Logs:** `docker logs neo4j_dashboard_keycloak`
- **Check Events:** Keycloak → Events → Login events (shows login attempts)

---

**You're all set!** 🎉

Start by accessing the admin console and exploring the Users section. The interface is intuitive, and you can always refer back to these guides.
