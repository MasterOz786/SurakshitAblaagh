# OAuth Integration Setup Guide

## Overview

OAuth 2.0 authentication has been integrated into the SurakshitAblaagh E2EE messaging system. Currently supports **Google OAuth**, with the architecture designed to easily extend to other providers (GitHub, Facebook, etc.).

## Features

- ✅ Google OAuth 2.0 integration
- ✅ Secure state token for CSRF protection
- ✅ Automatic user registration for OAuth users
- ✅ E2EE key pair generation for OAuth users
- ✅ Security logging for OAuth events
- ✅ Frontend OAuth button with Google branding

## Setup Instructions

### 1. Create Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable **Google+ API** (or Google Identity API)
4. Go to **Credentials** → **Create Credentials** → **OAuth 2.0 Client ID**
5. Configure OAuth consent screen:
   - User Type: External (for testing) or Internal
   - App name: SurakshitAblaagh
   - Scopes: `email`, `profile`, `openid`
6. Create OAuth 2.0 Client ID:
   - Application type: Web application
   - Authorized redirect URIs:
     - `http://localhost:3000/api/auth/oauth/google/callback` (development)
     - `https://yourdomain.com/api/auth/oauth/google/callback` (production)
7. Copy **Client ID** and **Client Secret**

### 2. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# Google OAuth
OAUTH_GOOGLE_CLIENT_ID=your_client_id_here
OAUTH_GOOGLE_CLIENT_SECRET=your_client_secret_here

# Frontend URL (for redirects)
FRONTEND_URL=http://localhost:5173

# Optional: MongoDB
MONGODB_URI=mongodb://localhost:27017
DB_NAME=surakshitablaagh_e2ee
```

### 3. Frontend Configuration (Optional)

If you want to use environment variables in the frontend, create `.env` in `client/`:

```bash
VITE_OAUTH_GOOGLE_CLIENT_ID=your_client_id_here
```

Or hardcode in `client/src/services/api.js` (line with `getOAuthUrl`).

### 4. Start the Server

```bash
# Install dependencies (if not already done)
npm install

# Start server
npm start
# or
node src/app.js
```

## How It Works

### Flow:

1. **User clicks "Continue with Google"** on login page
2. **Frontend** requests OAuth URL from backend
3. **Backend** generates secure state token and returns Google OAuth URL
4. **User** redirected to Google login page
5. **User** authenticates with Google
6. **Google** redirects back to `/api/auth/oauth/google/callback` with authorization code
7. **Backend** exchanges code for access token
8. **Backend** fetches user info from Google
9. **Backend** creates/updates user account
10. **Backend** redirects to frontend with user info
11. **Frontend** generates E2EE key pair and logs user in

### Security Features:

- **State Token**: CSRF protection using random state tokens
- **State Expiration**: States expire after 10 minutes
- **Secure Storage**: OAuth users get same E2EE key storage as regular users
- **Logging**: All OAuth events logged to `security.log`

## API Endpoints

### Get OAuth Authorization URL
```
GET /api/auth/oauth/:provider/authorize?redirect_uri=...&client_id=...
```

### OAuth Callback (handled by backend)
```
GET /api/auth/oauth/:provider/callback?code=...&state=...
```

## Testing

### Test OAuth Flow:

1. Start server: `node src/app.js`
2. Open frontend: `http://localhost:5173`
3. Click "Continue with Google" button
4. Complete Google authentication
5. Should redirect back and log you in

### Test Without Google Credentials:

The system will show an error if OAuth credentials are not configured. You can still use regular username/password authentication.

## Extending to Other Providers

To add support for other OAuth providers (GitHub, Facebook, etc.):

1. Add provider config to `OAUTH_PROVIDERS` in `src/auth/oauth.js`
2. Add provider routes in `src/auth/routes.js`
3. Add provider button in `client/src/components/Login.jsx`

Example for GitHub:
```javascript
github: {
  authUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  scope: 'user:email'
}
```

## Troubleshooting

### "OAuth credentials not configured"
- Make sure `.env` file exists with `OAUTH_GOOGLE_CLIENT_ID` and `OAUTH_GOOGLE_CLIENT_SECRET`

### "Invalid state parameter"
- State tokens expire after 10 minutes
- Make sure you're not reusing old authorization URLs

### Redirect URI mismatch
- Make sure redirect URI in Google Console matches exactly:
  - Development: `http://localhost:3000/api/auth/oauth/google/callback`
  - Production: `https://yourdomain.com/api/auth/oauth/google/callback`

### CORS errors
- Make sure `FRONTEND_URL` in `.env` matches your frontend URL
- Check CORS configuration in `src/app.js`

## Security Notes

- OAuth state tokens are stored in memory (cleared on server restart)
- Client secrets should NEVER be exposed to frontend
- Use HTTPS in production
- OAuth users still get full E2EE protection with client-side key generation

## Files Modified/Created

- `src/auth/oauth.js` - OAuth implementation
- `src/auth/routes.js` - OAuth routes
- `client/src/components/Login.jsx` - OAuth button
- `client/src/App.jsx` - OAuth callback handler
- `client/src/services/api.js` - OAuth API functions

