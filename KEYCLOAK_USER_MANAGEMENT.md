# Keycloak User Management Guide

This guide explains how to add new users to your project via Keycloak and how their roles/permissions are determined in the dashboard.

## Quick Summary

1.  **Add User**: Create the user in the **Keycloak Admin Console**.
2.  **Basic Access**: By default, new users get **Query User** access (Role 1) in the Dashboard.
3.  **Admin Access**:
    *   To give access to the **Django Admin Console** (`/admin`), you must assign the `admin` role in Keycloak.
    *   To give full access to **Dashboard Features** (like Admin Queries), you must update usage the **Django Admin Console** to set their "Role" to "Admin User".

---

## Part 1: Adding a New User in Keycloak

1.  Open the Keycloak Admin Console: [http://localhost:8080/admin](http://localhost:8080/admin) (or your deployed URL).
2.  Login with the admin credentials (default: `admin` / `admin`).
    *   *Note: If you used the setup script, the password might be `admin123`.*
3.  Ensure you are in the **`neo4j_dashboard`** realm (select it from the top-left dropdown if it says "Master").
4.  In the left menu, click **Users**.
5.  Click **Add user**.
6.  Fill in the form:
    *   **Username**: Required (e.g., `johndoe`).
    *   **Email**: Recommended.
    *   **First Name / Last Name**: Recommended.
    *   **Email Verified**: Toggle to **On** (unless you want them to verify via email).
7.  Click **Create**.
8.  Go to the **Credentials** tab.
9.  Click **Set Password**.
    *   Enter a password.
    *   Toggle **Temporary** to **Off** (unless you want to force a change on first login).
    *   Click **Save**.

**Result**: The user can now log in to the Dashboard. By default, they will have **Query User** permissions (ReadOnly access to predefined queries).

---

## Part 2: Understanding Roles & Permissions

There are two layers of permissions in this project:

### 1. Infrastructure Roles (Keycloak → Django Admin)
These roles control access to the **Django Admin Interface** (`http://localhost:8000/admin`). They are mapped from Keycloak roles.

*   **Keycloak Role: `admin`**
    *   **Effect**: Makes the user a **Superuser** in Django.
    *   **Access**: Full access to the Django Admin Console.
    *   **How to assign**:
        1.  In Keycloak, go to **Realm roles**.
        2.  If `admin` doesn't exist, click **Create role** -> Name it `admin` -> Save.
        3.  Go to **Users** -> Click the user -> **Role mapping**.
        4.  Click **Assign role** -> Select `admin` -> Assign.

*   **Keycloak Role: `staff`**
    *   **Effect**: Makes the user **Staff** in Django.
    *   **Access**: Limited access to the Django Admin Console.
    *   **How to assign**: Same as above, but create/assign a role named `staff`.

### 2. Dashboard Application Roles (Project Features)
These roles control what features the user sees in the **Project Dashboard** (e.g., Add Nodes, Admin Queries).

*   **Role 1: Query User** (Default)
    *   Access: View Predefined Queries, Explore Layers.
*   **Role 2: Node User**
    *   Access: All valid queries + **Add Nodes**, **Manual Query**.
*   **Role 3: Admin User**
    *   Access: Everything + **Admin Queries**, **User Management**.

**Access to Project Items**:
Currently, these Dashboard Roles are **NOT automatically mapped** from Keycloak. Even if you give someone the `admin` role in Keycloak, they will enter the Dashboard as a "Query User" (Role 1), although they will have Superuser access to the Django backend.

### How to Upgrade a User's Dashboard Role

1.  Log in to the **Django Admin Console** ([http://localhost:8000/admin](http://localhost:8000/admin)).
    *   *You need to be a Superuser (like the initial `admin` user).*
2.  Click on **Users** (under the Dashboard app, or Authentication).
3.  Click on the username of the user you want to upgrade.
4.  Scroll down to the **Role** field.
5.  Change the value to:
    *   **Node User** (for data entry capability)
    *   **Admin User** (for full project control)
6.  Click **Save**.

The next time getting user information, your dashboard will reflect these new permissions.

---

## Summary of Logic

| Feature | Controlled By | How to Change |
| :--- | :--- | :--- |
| **Log In** | Keycloak Existence | Create User in Keycloak |
| **Access Django Admin** | Keycloak Role (`admin`) | Assign `admin` role in Keycloak |
| **Add Nodes / Edit Data** | Django User Model (`role`) | Edit User in Django Admin -> Set Role to 'Node User' |
| **See Admin Queries** | Django User Model (`role`) | Edit User in Django Admin -> Set Role to 'Admin User' |

> **Pro Tip**: If you want Keycloak roles to *automatically* set the Dashboard Role (e.g. Keycloak `admin` -> Dashboard `Admin User`), we can add a small code update to `dashboard/auth.py` to handle this mapping. Let me know if you would like me to implement this!
