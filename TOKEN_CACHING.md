# Fraugster Integration - Token Caching Implementation

## Overview
This implementation follows Fraugster's best practices for token management:
- ✅ Authenticate once and cache token for 24 hours
- ✅ **JWT token decoding** to extract real expiry time
- ✅ Automatic token refresh on 401 (expired token)
- ✅ Retry failed requests with new token
- ✅ No unnecessary authentication calls
- ✅ Precise token expiry tracking

## API Endpoints

### Authentication Endpoints

#### `POST /auth/session`
Manually trigger authentication and cache the token.
```bash
curl -X POST http://localhost:3000/auth/session
```

#### `GET /auth/token`
Get the current valid token (reuses cached token if still valid).
```bash
curl -X GET http://localhost:3000/auth/token
```

#### `GET /auth/token-info`
Get detailed token information (expiry time, issued time, time remaining).
```bash
curl -X GET http://localhost:3000/auth/token-info
```
Response example:
```json
{
  "cached": true,
  "issuedAt": "2025-10-16T12:00:00.000Z",
  "expiresAt": "2025-10-17T12:00:00.000Z",
  "hoursUntilExpiry": 23.5,
  "isExpired": false
}
```

#### `DELETE /auth/session`
Clear the cached token (logout).
```bash
curl -X DELETE http://localhost:3000/auth/session
```

### Fraugster API Endpoints

#### `POST /api/transaction`
Send a transaction to Fraugster (automatically handles token).
```bash
curl -X POST http://localhost:3000/api/transaction \
  -H "Content-Type: application/json" \
  -d '{"your": "data"}'
```

#### `GET /api/transaction/:id`
Get transaction status (automatically handles token).
```bash
curl -X GET http://localhost:3000/api/transaction/12345
```

## How It Works

### Token Caching Flow with JWT Decoding
1. **First Request**: Authenticates with Fraugster
2. **JWT Decoding**: Extracts real expiry time from token's `exp` claim
3. **Token Caching**: Stores token with precise expiry timestamp
4. **Subsequent Requests**: Reuses cached token until actual expiry
5. **Token Expiry**: Automatically re-authenticates when token expires
6. **401 Response**: Clears cache, gets new token, retries request

### JWT Token Decoding
The service automatically decodes JWT tokens to extract:
- **`exp`** (Expiry): Precise token expiration timestamp
- **`iat`** (Issued At): When the token was issued
- **`sub`** (Subject): Token subject/user identifier

Benefits:
- ✅ Uses token for full validity period (no wasted time)
- ✅ Precise expiry tracking (no arbitrary 23-hour limit)
- ✅ Better logging and monitoring
- ✅ Automatic fallback if token is not JWT or missing claims

### Architecture

```
┌─────────────────┐
│ Controller      │ (receives HTTP requests)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Service         │ (business logic)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ AuthService     │ (token management + API calls)
├─────────────────┤
│ - cachedToken   │ (stores token)
│ - tokenExpiry   │ (stores expiry time)
│ - getValidToken │ (returns cached or new token)
│ - makeAuthReq   │ (auto-retry on 401)
└─────────────────┘
```

## Usage Example

### In TransactionService
```typescript
// No need to manually authenticate!
// Just call makeAuthenticatedRequest()
async sendTransaction(data: any): Promise<any> {
  return this.authService.makeAuthenticatedRequest(
    '/api/v2/transactions',
    'POST',
    data,
  );
}
```

The `makeAuthenticatedRequest` method:
- ✅ Automatically gets a valid token
- ✅ Reuses cached token if still valid
- ✅ Refreshes token if expired
- ✅ Retries request on 401 error

## Performance Benefits

**Without Token Caching** (❌ Bad):
- Request 1: Auth (500ms) + API (200ms) = 700ms
- Request 2: Auth (500ms) + API (200ms) = 700ms
- Request 3: Auth (500ms) + API (200ms) = 700ms
- **Total: 2100ms**

**With Token Caching** (✅ Good):
- Request 1: Auth (500ms) + API (200ms) = 700ms
- Request 2: API (200ms) = 200ms
- Request 3: API (200ms) = 200ms
- **Total: 1100ms (52% faster!)**

## Environment Variables

Make sure your `.env` file contains:
```env
FRAUGSTER_USERNAME=your_username
FRAUGSTER_PASSWORD=your_password
FRAUGSTER_BASE_URL=https://api.fraugsterapi.com
```

## Logging

The service uses **Winston** for advanced logging with multiple transports:

### Log Levels
- `error`: Critical errors and authentication failures
- `warn`: Warnings (token expiry, retries)
- `info`: General information (successful auth, token usage)
- `debug`: Detailed debugging information
- `http`: HTTP request/response details

### Log Transports
- **Console**: Colored output for development
- **File (logs/error.log)**: JSON format for errors only
- **File (logs/all.log)**: JSON format for all logs

### Log Format
```
2025-10-16 17:04:30:123 info: [AuthService] Authenticating with Fraugster API...
2025-10-16 17:04:31:456 info: [AuthService] Authentication successful, token cached until 2025-10-17T17:04:31.456Z
```

### Environment Variables
```env
LOG_LEVEL=debug  # Set log level (error, warn, info, debug)
NODE_ENV=production  # Disable console colors in production
```

## Testing

1. Start the server:
```bash
npm run start:dev
```

2. Test authentication:
```bash
curl -X POST http://localhost:3000/auth/session
```

3. Test with actual Fraugster endpoint:
```bash
curl -X POST http://localhost:3000/api/transaction \
  -H "Content-Type: application/json" \
  -d '{"your": "data"}'
```

Watch the server logs to see:
- First request: "Authenticating with Fraugster API..."
- Subsequent requests: "Using cached token"
- On expiry: "Token expired, re-authenticating..."

## Notes

- Token is cached in memory (resets on server restart)
- For production with multiple instances, consider Redis for token storage
- Token expiry set to 23 hours (1 hour safety margin from 24h max)
- Automatic retry happens only once per request to prevent loops
