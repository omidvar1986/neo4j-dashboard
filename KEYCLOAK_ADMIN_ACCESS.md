# Keycloak Admin Console Access

## Changes Implemented

1.  **Updated Navbar Link:**
    - The "Keycloak Console" button in the navbar now links directly to:
      `http://localhost:8080/admin/master/console/`
    - Visibility: **Admin users only**

2.  **Added Dashboard Card:**
    - Added a new "Keycloak Admin" card to the main dashboard (`http://127.0.0.1:8000/`).
    - Position: **First card** in the project list.
    - Visibility: **Admin users only**
    - Features:
        - Key icon
        - "Open Console" button linking to `http://localhost:8080/admin/master/console/`
        - Opens in a new tab (`target="_blank"`)

## How to Verify

1.  **Logout** from your current session (use the simplified logout which now works!).
2.  **Log in as Admin:**
    - Username: `admin`
    - Password: `admin123`
3.  **Check Dashboard:**
    - You should see the **Keycloak Admin** card.
    - You should see the **Keycloak Console** button in the navbar.
4.  **Click the Button:**
    - It should open the Keycloak Admin Console in a new tab.

## Why You Might Not See It

If you are logged in as `testuser` or any valid user WITHOUT the `admin` role, these buttons will be **hidden**. The access control is strictly enforced:

```python
{% if user.can_access_admin_queries %}
    <!-- Keycloak Admin Content -->
{% endif %}
```

Users must have the appropriate admin role (usually role ID 3 or superuser status) to see these elements.
