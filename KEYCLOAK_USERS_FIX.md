# Keycloak Users Fix - December 8, 2025

## Problem Identified

The login issue was caused by a **missing admin user in Keycloak**. The setup script was supposed to create 2 users in the Keycloak `neo4j_dashboard` realm:

1. **testuser** (password: `password`)
2. **admin** (password: `admin123`)

However, only `testuser` was being created.

## Root Cause

The user existence check in `setup_all.sh` was using `grep -q "$ADMIN_USER"` which could produce false positives. When checking for the "admin" user, the grep command would match the word "admin" in other parts of the JSON output (like in the "access" field containing `"manage" : true`), causing the script to incorrectly think the user already existed and skip creation.

## Solution Applied

### 1. Immediate Fix (Manual)
Created the missing admin user manually:
```bash
docker exec -i neo4j_dashboard_keycloak /opt/keycloak/bin/kcadm.sh create users -r neo4j_dashboard -s username=admin -s enabled=true -s email="admin@example.com" -s firstName="Admin" -s lastName="User"
docker exec -i neo4j_dashboard_keycloak /opt/keycloak/bin/kcadm.sh set-password -r neo4j_dashboard --username admin --new-password "admin123"
```

### 2. Permanent Fix (Script Update)
Updated `setup_all.sh` to use a more reliable user existence check:

**Before:**
```bash
if ! $KCADM get users -r $KEYCLOAK_REALM -q username=$ADMIN_USER | grep -q "$ADMIN_USER"; then
```

**After:**
```bash
ADMIN_CHECK=$($KCADM get users -r $KEYCLOAK_REALM -q username=$ADMIN_USER 2>/dev/null | tr -d '[:space:]')
if [ "$ADMIN_CHECK" = "[]" ]; then
```

This checks if the JSON response is exactly `[]` (empty array), which reliably indicates the user doesn't exist.

## Current Status

✅ **Both users now exist in Keycloak:**

| Username  | Password  | Email              | First Name | Last Name |
|-----------|-----------|-------------------|------------|-----------|
| testuser  | password  | test@example.com  | Test       | User      |
| admin     | admin123  | admin@example.com | Admin      | User      |

## How to Verify

You can verify the users exist by running:
```bash
docker exec -i neo4j_dashboard_keycloak /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin
docker exec -i neo4j_dashboard_keycloak /opt/keycloak/bin/kcadm.sh get users -r neo4j_dashboard --fields username,email
```

## Testing Login

You can now log in with either user:

1. **Admin User:**
   - Username: `admin`
   - Password: `admin123`

2. **Test User:**
   - Username: `testuser`
   - Password: `password`

## Notes

- The Django superuser (admin/admin123) is separate from the Keycloak users
- When Keycloak authentication is enabled, users must exist in BOTH Django and Keycloak
- The setup script now properly creates both users on fresh installations
- The script also provides feedback when users already exist
