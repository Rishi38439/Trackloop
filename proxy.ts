import { NextRequest, NextResponse } from 'next/server';

const PROTECTED_API_PREFIXES = [
  '/api/activity-log',
  '/api/activity-delete',
];

const AUTH_COOKIE_NAMES = ['trakloop_session', 'trackdaily_session'];

function getAuthSecret(): string {
  const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    return 'trakloop_dev_cryptographically_secure_fallback_secret_32chars!';
  }
  return secret;
}

function extractToken(request: NextRequest): string | null {
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.substring(7).trim();
    if (bearer) return bearer;
  }

  for (const cookieName of AUTH_COOKIE_NAMES) {
    const val = request.cookies.get(cookieName)?.value;
    if (val) return val;
  }

  return null;
}

function hasTrustedOrigin(request: NextRequest): boolean {
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

async function verifyTokenSignature(token: string, secret: string): Promise<{ valid: boolean; tokenId?: string }> {
  if (!token || !token.includes('.')) return { valid: false };
  const parts = token.split('.');
  if (parts.length !== 2) return { valid: false };
  const [tokenId, signature] = parts;
  if (!tokenId || !signature) return { valid: false };

  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign('HMAC', key, enc.encode(tokenId));
    const base64url = Buffer.from(signatureBuffer).toString('base64url');

    if (base64url === signature) {
      return { valid: true, tokenId };
    }
    return { valid: false };
  } catch (error) {
    console.error('Error verifying token in middleware:', error);
    return { valid: false };
  }
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // CSRF Origin verification for state-modifying requests to API
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method) && pathname.startsWith('/api/')) {
    if (!hasTrustedOrigin(request)) {
      return NextResponse.json(
        { error: 'Cross-site request forgery protection: untrusted origin' },
        { status: 403 }
      );
    }
  }

  // Check if route requires authentication
  const isProtectedApi = PROTECTED_API_PREFIXES.some(prefix => pathname.startsWith(prefix));

  if (isProtectedApi) {
    const token = extractToken(request);
    if (!token) {
      return NextResponse.json(
        { error: 'Authentication required. No session credentials provided.' },
        { status: 401 }
      );
    }

    const verification = await verifyTokenSignature(token, getAuthSecret());
    if (!verification.valid) {
      return NextResponse.json(
        { error: 'Invalid or forged authentication credentials.' },
        { status: 401 }
      );
    }

    // Attach validated token header to downstream request
    const requestHeaders = new Headers(request.headers);
    if (verification.tokenId) {
      requestHeaders.set('x-authenticated-token-id', verification.tokenId);
    }

    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};

export default proxy;
