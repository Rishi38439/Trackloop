import 'server-only';

import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { AuthSessionDocument, AuthUserDocument, getAuthSessionCollection, getAuthUserCollection, getLoginCodeCollection } from './mongodb';
import { sanitizeNoSql, generateSecureLoginCode, hashLoginCode, verifyLoginCode } from './authSecurity';
import { isValidMobileNumber, normalizeMobileNumber } from './phone';

export const SESSION_COOKIE_NAME = 'trakloop_session';
export const LEGACY_COOKIE_NAME = 'trackdaily_session';
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const BCRYPT_ROUNDS = 12;

export type SafeUser = Pick<AuthUserDocument, 'id' | 'name' | 'email' | 'phoneNumber'>;

export function toSafeUser(user: AuthUserDocument): SafeUser {
  return { id: user.id, name: user.name, email: user.email, phoneNumber: user.phoneNumber };
}

export function getAuthSecret(): string {
  const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET or SESSION_SECRET must be set to a cryptographically secure value of at least 32 characters in production');
    }
    return 'trakloop_dev_cryptographically_secure_fallback_secret_32chars!';
  }
  return secret;
}

export const registrationSchema = z.object({
  name: z.string()
    .trim()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be at most 100 characters'),
  email: z.string()
    .trim()
    .toLowerCase()
    .email('Please enter a valid email address'),
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .max(72, 'Password must not exceed 72 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

export const loginSchema = z.object({
  email: z.string()
    .trim()
    .toLowerCase()
    .email('Please enter a valid email address'),
  password: z.string()
    .min(1, 'Password is required')
    .max(72, 'Password must not exceed 72 characters'),
});

export function normalizeEmail(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function validateRegistration(input: Record<string, unknown>): { name: string; email: string; password: string } | { error: string } {
  const sanitized = sanitizeNoSql(input);
  const result = registrationSchema.safeParse(sanitized);
  if (!result.success) {
    return { error: result.error.errors[0]?.message || 'Invalid registration details' };
  }
  return result.data;
}

export function validateLoginInput(input: Record<string, unknown>): { email: string; password: string } | { error: string } {
  const sanitized = sanitizeNoSql(input);
  const result = loginSchema.safeParse(sanitized);
  if (!result.success) {
    return { error: result.error.errors[0]?.message || 'Invalid email or password format' };
  }
  return result.data;
}

// Phone-based authentication schemas
export const phoneSignUpSchema = z.object({
  name: z.string()
    .trim()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be at most 100 characters'),
  mobileNumber: z.string()
    .trim()
    .min(7, 'Please enter a valid mobile number'),
});

export const phoneLoginSchema = z.object({
  mobileNumber: z.string()
    .trim()
    .min(7, 'Please enter a valid mobile number'),
  loginCode: z.string()
    .trim()
    .length(6, 'Login code must be exactly 6 characters'),
});

export function validatePhoneSignUp(input: Record<string, unknown>): { name: string; mobileNumber: string } | { error: string } {
  const sanitized = sanitizeNoSql(input);
  const result = phoneSignUpSchema.safeParse(sanitized);
  if (!result.success) {
    return { error: result.error.errors[0]?.message || 'Invalid signup details' };
  }
  
  const normalized = normalizeMobileNumber(result.data.mobileNumber);
  if (!isValidMobileNumber(normalized)) {
    return { error: 'Please enter a valid mobile number' };
  }
  
  return { name: result.data.name, mobileNumber: normalized };
}

export function validatePhoneLogin(input: Record<string, unknown>): { mobileNumber: string; loginCode: string } | { error: string } {
  const sanitized = sanitizeNoSql(input);
  const result = phoneLoginSchema.safeParse(sanitized);
  if (!result.success) {
    return { error: result.error.errors[0]?.message || 'Invalid login details' };
  }
  
  const normalized = normalizeMobileNumber(result.data.mobileNumber);
  if (!isValidMobileNumber(normalized)) {
    return { error: 'Please enter a valid mobile number' };
  }
  
  return { mobileNumber: normalized, loginCode: result.data.loginCode };
}

export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
  return bcrypt.hash(password, salt);
}

export async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
  if (!password || !passwordHash) return false;
  return bcrypt.compare(password, passwordHash);
}

export async function createUser(name: string, email: string, password: string): Promise<SafeUser | null> {
  const users = await getAuthUserCollection();
  const normalizedEmail = email.trim().toLowerCase();
  
  const existing = await users.findOne({ email: normalizedEmail });
  if (existing) return null;

  const now = new Date();
  const passwordHash = await hashPassword(password);
  const user: AuthUserDocument = {
    id: crypto.randomUUID(),
    name: name.trim(),
    email: normalizedEmail,
    passwordHash,
    isActive: true,
    createdAt: now,
    updatedAt: now,
  };

  try {
    await users.insertOne(user);
    return toSafeUser(user);
  } catch (error: unknown) {
    if (typeof error === 'object' && error && 'code' in error && error.code === 11000) {
      return null;
    }
    throw error;
  }
}

export async function authenticateUser(email: string, password: string): Promise<SafeUser | null> {
  const users = await getAuthUserCollection();
  const normalizedEmail = email.trim().toLowerCase();
  const user = await users.findOne({ email: normalizedEmail });

  if (!user || !user.passwordHash) {
    // Perform dummy bcrypt comparison to mitigate timing attacks
    await bcrypt.compare(password, '$2b$12$e8Yk26lAqv0i3c2DkXQ6vOnf9b3M4OQZ9lZq8kQ7q1s2t3u4v5w6x');
    return null;
  }

  const matches = await verifyPassword(password, user.passwordHash);
  if (!matches) return null;

  return toSafeUser(user);
}

/**
 * Create a user via phone-based registration after OTP verification.
 * The user's phone number has already been verified at this point.
 * A login code is automatically generated.
 */
export async function createPhoneBasedUser(name: string, mobileNumber: string): Promise<{ user: SafeUser; loginCode: string } | null> {
  const users = await getAuthUserCollection();
  const normalizedPhone = normalizeMobileNumber(mobileNumber);
  
  // Check if phone number already exists
  const existing = await users.findOne({ phoneNumber: normalizedPhone });
  if (existing) return null;

  const now = new Date();
  const loginCode = await generateSecureLoginCode();
  const loginCodeHash = await hashLoginCode(loginCode);
  
  const user: AuthUserDocument = {
    id: crypto.randomUUID(),
    name: name.trim(),
    email: `phone_${crypto.randomUUID()}@trackdaily.local`,
    phoneNumber: normalizedPhone,
    phoneNumberVerified: true,
    passwordHash: await hashPassword(crypto.randomUUID()), // Placeholder, not used for phone auth
    loginCodeHash,
    loginCodeVersion: 1,
    isActive: true,
    createdAt: now,
    updatedAt: now,
  };

  try {
    await users.insertOne(user);
    
    // Store login code separately
    const codesCollection = await getLoginCodeCollection();
    await codesCollection.insertOne({
      userId: user.id,
      codeHash: loginCodeHash,
      codeVersion: 1,
      createdAt: now,
    });
    
    return { user: toSafeUser(user), loginCode };
  } catch (error: unknown) {
    if (typeof error === 'object' && error && 'code' in error && error.code === 11000) {
      return null;
    }
    throw error;
  }
}

/**
 * Authenticate a user with mobile number + login code combination.
 * Both credentials are required for successful authentication.
 */
export async function authenticatePhoneUser(mobileNumber: string, loginCode: string): Promise<SafeUser | null> {
  const users = await getAuthUserCollection();
  const normalizedPhone = normalizeMobileNumber(mobileNumber);
  const user = await users.findOne({ 
    phoneNumber: normalizedPhone,
    phoneNumberVerified: true,
    isActive: true,
  });

  if (!user || !user.loginCodeHash) {
    // Perform dummy bcrypt comparison to mitigate timing attacks
    await verifyLoginCode(loginCode, '$2b$12$e8Yk26lAqv0i3c2DkXQ6vOnf9b3M4OQZ9lZq8kQ7q1s2t3u4v5w6x');
    return null;
  }

  const matches = await verifyLoginCode(loginCode, user.loginCodeHash);
  if (!matches) return null;

  return toSafeUser(user);
}

/**
 * Regenerate a user's login code.
 * The old code is invalidated immediately.
 * This should only be called after OTP verification.
 */
export async function regenerateUserLoginCode(userId: string): Promise<string | null> {
  const users = await getAuthUserCollection();
  const user = await users.findOne({ id: userId, isActive: true });

  if (!user) return null;

  const newLoginCode = await generateSecureLoginCode();
  const newCodeHash = await hashLoginCode(newLoginCode);
  const now = new Date();

  // Update user with new code
  await users.updateOne(
    { id: userId },
    {
      $set: {
        loginCodeHash: newCodeHash,
        loginCodeVersion: (user.loginCodeVersion ?? 0) + 1,
        lastLoginCodeRegeneratedAt: now,
        updatedAt: now,
      },
    }
  );

  // Update login codes collection
  const codesCollection = await getLoginCodeCollection();
  await codesCollection.deleteMany({ userId });
  await codesCollection.insertOne({
    userId,
    codeHash: newCodeHash,
    codeVersion: (user.loginCodeVersion ?? 0) + 1,
    createdAt: now,
  });

  return newLoginCode;
}

/**
 * Update the last login timestamp for a user.
 */
export async function recordUserLogin(userId: string): Promise<void> {
  const users = await getAuthUserCollection();
  await users.updateOne(
    { id: userId },
    { $set: { lastLoginAt: new Date(), updatedAt: new Date() } }
  );
}

/**
 * Creates a cryptographically signed session token.
 * Token format: <tokenId>.<signature>
 * Only the SHA-256 hash of the entire token is stored in the database.
 */
export async function createAuthenticatedSession(userId: string): Promise<string> {
  const tokenId = crypto.randomBytes(32).toString('base64url');
  const secret = getAuthSecret();
  const signature = crypto.createHmac('sha256', secret).update(tokenId).digest('base64url');
  const rawToken = `${tokenId}.${signature}`;

  const tokenHash = hashSessionToken(rawToken);
  const now = new Date();
  const session: AuthSessionDocument = {
    tokenHash,
    userId,
    createdAt: now,
    expiresAt: new Date(now.getTime() + SESSION_DURATION_MS),
  };

  const sessions = await getAuthSessionCollection();
  await sessions.insertOne(session);
  return rawToken;
}

export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function verifyTokenSignature(token: string): boolean {
  if (!token || !token.includes('.')) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [tokenId, signature] = parts;
  if (!tokenId || !signature) return false;

  const expectedSig = crypto.createHmac('sha256', getAuthSecret()).update(tokenId).digest('base64url');
  if (signature.length !== expectedSig.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig));
}

export function extractTokenFromRequest(request: NextRequest): string | null {
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.substring(7).trim();
    if (bearer) return bearer;
  }

  const cookie = request.cookies.get(SESSION_COOKIE_NAME)?.value
    ?? request.cookies.get(LEGACY_COOKIE_NAME)?.value;
  return cookie || null;
}

export async function getAuthenticatedUser(request: NextRequest): Promise<SafeUser | null> {
  const token = extractTokenFromRequest(request);
  if (!token) return null;

  if (!verifyTokenSignature(token)) {
    return null;
  }

  const tokenHash = hashSessionToken(token);
  const sessions = await getAuthSessionCollection();
  const session = await sessions.findOne({
    tokenHash,
    expiresAt: { $gt: new Date() },
    revokedAt: { $exists: false },
  });

  if (!session) return null;

  const users = await getAuthUserCollection();
  const user = await users.findOne({ id: session.userId });
  return user ? toSafeUser(user) : null;
}

export async function revokeAuthenticatedSession(request: NextRequest): Promise<void> {
  const token = extractTokenFromRequest(request);
  if (token) {
    const tokenHash = hashSessionToken(token);
    const sessions = await getAuthSessionCollection();
    await sessions.updateOne(
      { tokenHash },
      { $set: { revokedAt: new Date() } },
    );
  }
}

export async function requireAuthenticatedUser(request: NextRequest): Promise<SafeUser | NextResponse> {
  const user = await getAuthenticatedUser(request);
  return user ?? NextResponse.json({ error: 'Authentication required' }, { status: 401 });
}

export function setSessionCookie(response: NextResponse, token: string): void {
  response.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: token,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_DURATION_MS / 1000,
  });
}

export function clearSessionCookie(response: NextResponse): void {
  response.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: '',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });

  // Also clear legacy cookie if present
  response.cookies.set({
    name: LEGACY_COOKIE_NAME,
    value: '',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

export function hasTrustedOrigin(request: NextRequest): boolean {
  const origin = request.headers.get('origin');
  if (!origin) return true;

  try {
    const originUrl = new URL(origin);
    const forwardedHost = request.headers.get('x-forwarded-host');
    const requestHost = forwardedHost?.split(',')[0]?.trim()
      ?? request.headers.get('host')
      ?? request.nextUrl.host;

    // Direct host match (handles reverse proxies and CDNs where protocol might differ)
    if (originUrl.host === requestHost) {
      return true;
    }

    const forwardedProto = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim();
    const requestProtocol = forwardedProto || request.nextUrl.protocol.replace(':', '');
    const configuredOrigin = process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL;

    const trustedOrigins = new Set([
      `${requestProtocol}://${requestHost}`,
      request.nextUrl.origin,
      ...(configuredOrigin ? [new URL(configuredOrigin).origin] : []),
    ]);

    // Automatically trust Netlify deployment URLs if present
    for (const netlifyEnv of [process.env.URL, process.env.DEPLOY_PRIME_URL, process.env.DEPLOY_URL]) {
      if (netlifyEnv) {
        try {
          trustedOrigins.add(new URL(netlifyEnv).origin);
        } catch {
          // ignore malformed URLs
        }
      }
    }

    if (process.env.NODE_ENV !== 'production') {
      trustedOrigins.add(`http://localhost:${request.nextUrl.port || '3000'}`);
      trustedOrigins.add(`http://127.0.0.1:${request.nextUrl.port || '3000'}`);
    }

    return trustedOrigins.has(originUrl.origin);
  } catch {
    return false;
  }
}

export function getClientAddress(request: NextRequest): string {
  return request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    ?? request.headers.get('x-real-ip')
    ?? 'unknown';
}
