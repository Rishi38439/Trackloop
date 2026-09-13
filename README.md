# trakloop

A modern activity and momentum tracking full-stack application built with Next.js, featuring real-time analytics, production-grade authentication with secure password storage, session management, and a beautiful dark-themed interface.

## Features

### Authentication & Security
- **Secure Password Hashing**: Passwords are never stored in plain text. Hashed on the backend using `bcryptjs` (12 rounds) with unique cryptographic salts.
- **Cryptographic Session Security**: Session tokens are cryptographically signed with HMAC-SHA256 and verified via Next.js authentication middleware.
- **Database Hardening**: MongoDB stores only the SHA-256 hash of session tokens with automatic TTL expiration and revocation support. Sensitive fields (`passwordHash`, `jwtSecret`) are never exposed.
- **Brute-Force & Rate Limiting**: Intelligent rate limiting for register and login endpoints with exponential backoff and `Retry-After` headers.
- **NoSQL Injection & CSRF Protection**: Strict Zod schema validation, origin verification, and HttpOnly/SameSite secure cookies.

### Activity Tracking
- **Comprehensive Logging**: Track activities with names, durations, timestamps, and optional notes.
- **User-Isolated Storage**: Each user's data is fully isolated to their authenticated account.
- **Real-time Analytics**: Instant activity logging and immediate reflection in visual charts.

### Analytics & Visualization
- **Interactive Charts**: Dynamic visualizations showing activity trends and patterns over time.
- **Statistical Insights**: Comprehensive metrics including total activities, duration averages, and frequency analysis.
- **Time-based Analysis**: View activities by weekly, monthly, or yearly time ranges.

## Technology Stack

- **Framework**: Next.js 16 (App Router)
- **Database**: MongoDB with official driver
- **Authentication**: bcryptjs, crypto HMAC signatures, HttpOnly cookies, Next.js Middleware
- **Validation**: Zod schema validation
- **UI Library**: shadcn/ui components built on Radix UI primitives
- **Styling**: Tailwind CSS v4
- **Charts**: Recharts
- **Icons**: Lucide React
- **Animations**: Framer Motion
- **Package Manager**: pnpm

## Getting Started

### Prerequisites

- Node.js 18+ and pnpm package manager
- MongoDB instance (local or MongoDB Atlas)

### Environment Setup

1. Copy the example environment file:
```bash
cp .env.example .env.local
```

2. Configure environment variables in `.env.local`:
```env
MONGODB_URI=mongodb://127.0.0.1:27017
MONGODB_DB=trakloop

# Generate with: node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
JWT_SECRET=<your-random-32-byte-secret>
SESSION_SECRET=<your-random-32-byte-secret>
APP_URL=http://localhost:3000
SMS_PROVIDER=console
```

### Installation & Running

1. Install dependencies:
```bash
pnpm install
```

2. Run type check:
```bash
pnpm typecheck
```

3. Start development server:
```bash
pnpm dev
```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

## API Endpoints

- `POST /api/auth/register` - Create account with validated name, email, and strong password
- `POST /api/auth/login` - Authenticate with credentials and receive HttpOnly session cookie
- `POST /api/auth/register-phone` - Send OTP for phone registration
- `POST /api/auth/verify-phone-otp` - Verify OTP and create the phone account
- `POST /api/auth/login-phone` - Send OTP for phone login
- `POST /api/auth/verify-login` - Verify OTP and phone login code
- `POST /api/auth/regenerate-code` - Regenerate a login code after OTP confirmation
- `POST /api/auth/logout` - Invalidate session in database and clear session cookie
- `GET  /api/auth/me` - Retrieve authenticated user profile (`id`, `name`, `email`)
- `POST /api/activity-log` - Log activity (Protected via middleware & session)
- `POST /api/activity-delete` - Delete activity (Protected via middleware & session)

## Deploying to Netlify

This project is configured for automated zero-error deployment on Netlify using the Next.js OpenNext runtime (`@netlify/plugin-nextjs`).

### Step-by-Step Deployment Guide

1. **Push your code to GitHub / GitLab / Bitbucket**:
   Ensure all files including `netlify.toml`, `.npmrc`, and `package.json` are committed.

2. **Create a Site on Netlify**:
   - Go to [Netlify Dashboard](https://app.netlify.com)
   - Click **Add new site** > **Import an existing project**
   - Connect your Git repository

3. **Verify Build Settings** (automatically picked up from `netlify.toml`):
   - **Base directory**: `.` (leave empty or default)
   - **Build command**: `pnpm run build`
   - **Publish directory**: `.next`

4. **Configure Environment Variables** in Netlify Dashboard (**Site configuration** > **Environment variables**):
   - `MONGODB_URI`: Your MongoDB Atlas connection string (e.g. `mongodb+srv://<user>:<password>@cluster0.mongodb.net/?retryWrites=true&w=majority`)
   - `MONGODB_DB`: `trakloop`
   - `JWT_SECRET`: Minimum 32-character random string
   - `SESSION_SECRET`: Minimum 32-character random string
   - `APP_URL`: Your Netlify site URL (e.g. `https://your-site.netlify.app`)
   - `SMS_PROVIDER`: `console`, `twilio`, or `webhook`
   - `ALLOW_CONSOLE_SMS`: `true` (if using console provider in production to view OTP in Netlify Function logs)
   - If using Twilio: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`

5. **MongoDB Atlas Network Access**:
   - Since Netlify serverless functions run on dynamic cloud IPs, add `0.0.0.0/0` (Allow Access from Anywhere) to your MongoDB Atlas **Network Access** IP Access List.

6. **Trigger Deploy**:
   Click **Deploy site**. Netlify will install dependencies via pnpm, build the Next.js application, package the middleware and serverless functions, and publish your site.

## License

MIT
