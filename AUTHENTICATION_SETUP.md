# TrackDaily Authentication - Setup Guide

## Environment Variables

Add the following environment variables to your `.env.local` file:

```env
# Database
MONGODB_URI=mongodb://127.0.0.1:27017
MONGODB_DB=trakloop

# Authentication & Security
JWT_SECRET=your-cryptographically-secure-secret-key-min-32-chars
SESSION_SECRET=your-session-secret-key-min-32-chars

# Public origin used for CSRF validation
APP_URL=http://localhost:3000

# SMS Provider Configuration
# Use console only in development. Production must use twilio or webhook.
SMS_PROVIDER=console  # Options: console, twilio, webhook
SMS_API_KEY=your-api-key-here
SMS_SENDER_ID=your-sender-id-here
SMS_WEBHOOK_URL=https://your-sms-service.example/send

# Twilio configuration (required when SMS_PROVIDER=twilio)
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_FROM=+15551234567

# Node Environment
NODE_ENV=development
```

## Required Setup Steps

1. **Database**: Ensure MongoDB is running locally or configure MONGODB_URI
2. **Secrets**: Generate secure random strings for JWT_SECRET and SESSION_SECRET
3. **OTP**: In development, OTPs are logged to console. In production, configure an SMS provider

## SMS Providers

### Console (Development)
Logs OTP to server console. Useful for development and testing.

### Twilio
1. Create Twilio account at https://www.twilio.com
2. Get your Account SID, Auth Token, and a Twilio phone number
3. Set SMS_PROVIDER=twilio
4. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM

### Webhook
Configure an internal SMS gateway endpoint that accepts JSON with `to`, `message`, and `senderId` fields.
Set SMS_PROVIDER=webhook, SMS_WEBHOOK_URL, and optionally SMS_API_KEY for a Bearer token.

## Testing the Authentication Flow

### 1. Sign Up
- Click "Create an account"
- Enter name and mobile number
- Receive OTP (check console in development)
- Verify OTP
- System generates and displays login code
- Save the code securely

### 2. Login
- Enter mobile number and login code
- Click "Sign in"
- Receive OTP
- Verify OTP
- Access to Dashboard

### 3. Regenerate Login Code
- Go to Settings
- Click "Regenerate Login Code"
- Confirm action
- Receive OTP
- Verify OTP to get new code

## Development OTPs

When `NODE_ENV !== 'production'`, OTPs are exposed in API responses for testing:
- Check browser network tab or API response for `devOtp` field
- Console logs also show generated OTPs

Production rejects the console provider and never returns `devOtp`.

## Database Collections

The following MongoDB collections are automatically created:

- `users` - User accounts with phone numbers and login codes
- `auth_sessions` - Active sessions
- `otp_challenges` - Active OTP verification attempts
- `verification_tokens` - Used for OTP verification flow
- `rate_limits` - Rate limiting tracking
- `login_codes` - Login code history (for uniqueness checking)

## Security Considerations

1. **Login Codes**: Never sent via email or insecure channels
2. **OTPs**: Hashed with salt before storage
3. **Sessions**: Secure HTTP-only cookies with HMAC signatures
4. **Rate Limiting**: Protects against brute force attacks
5. **Phone Numbers**: Validated with E.164 format

## Troubleshooting

### OTP not sending
- Check SMS provider configuration
- Verify API keys are correct
- Check rate limits (max 5 requests per 10 minutes)
- In development, check server console for logs

### Login code not generated
- Check MongoDB connection
- Verify database permissions
- Check server logs for errors

### Session issues
- Clear browser cookies
- Check JWT_SECRET and SESSION_SECRET are set
- Verify session hasn't expired (30 days)
