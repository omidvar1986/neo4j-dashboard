# Authentication Guide for Neo4j Dashboard

## Overview

The Neo4j Dashboard now supports a unified authentication system that allows users to authenticate with either a **Session ID** or **User ID** from the Testnet Admin API. Once authenticated, all transaction management features work seamlessly without requiring manual token input.

## Authentication Methods

### Method 1: Session ID (Recommended)

**Most Secure Option** - Contains all authentication information including CSRF tokens.

1. Go to [Testnet Admin](https://testnetadminv2.ntx.ir) and log in
2. Open Developer Tools (F12) → Application/Storage → Cookies
3. Find `testnetadminv2.ntx.ir` domain
4. Copy the `sessionid` value (just the sessionid, not the csrftoken)
5. Paste it in the Session ID field in API Tools
6. Click "Authenticate & Extract User Info"

### Method 2: User ID (Alternative)

**Less Secure** - For testing purposes only.

1. Enter your User ID directly in the User ID field
2. Click "Authenticate & Extract User Info"

## How It Works

1. **Authentication**: When you enter a Session ID or User ID, the system automatically:
   - Extracts the user ID from the session
   - Fetches the CSRF token
   - Validates the session with the external API
   - Stores all authentication information in your Django session

2. **Automatic Usage**: Once authenticated, all features automatically use your stored credentials:
   - Transaction Management loads your transactions automatically
   - Add Transaction uses your authenticated session
   - All AJAX calls work without manual token input

3. **Session Persistence**: Your authentication persists across page refreshes and browser sessions until you log out or change authentication.

## Features That Use Authentication

- **Transaction Management**: View, confirm, reject, and edit transactions
- **Add Transaction**: Create new transactions for your user
- **Load Wallets**: Get available wallets for your user
- **Bulk Actions**: Perform bulk operations on multiple transactions

## Security Notes

- **Session ID** is the recommended method as it's more secure and contains all necessary authentication information
- **User ID** method is provided for testing but is less secure
- All authentication information is stored securely in Django sessions
- Sessions are automatically cleaned up when you log out

## Troubleshooting

### "No Authentication Found" Error
- Go to API Tools and authenticate with your Session ID or User ID
- Make sure you're using a valid session from Testnet Admin

### "Session Valid but User ID Not Extractable" Error
- This can happen with certain session formats
- Try using the User ID method instead
- Contact support if the issue persists

### "Access Denied" Error
- Your session may have expired
- Re-authenticate with a fresh Session ID from Testnet Admin
- Check if your IP is blocked by the external API

## API Endpoints

The following endpoints now use stored authentication:

- `GET /transaction-management/` - Main transaction management page
- `POST /get-transactions-ajax/` - Load user transactions
- `POST /transaction-action-ajax/` - Perform transaction actions
- `POST /load-wallets-ajax/` - Load user wallets
- `POST /add-transaction/` - Create new transactions

All these endpoints automatically use your stored authentication information and no longer require manual token input.
