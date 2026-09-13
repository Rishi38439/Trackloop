import 'server-only';

interface SmsProviderConfig {
  provider: string;
  apiKey?: string;
  senderId?: string;
}

function getConfig(): SmsProviderConfig {
  return {
    provider: (process.env.SMS_PROVIDER ?? (process.env.NODE_ENV === 'production' ? '' : 'console')).toLowerCase(),
    apiKey: process.env.SMS_API_KEY,
    senderId: process.env.SMS_SENDER_ID,
  };
}

function messageForOtp(otp: string): string {
  return `Your TrackDaily verification code is ${otp}. It expires in 5 minutes.`;
}

async function sendWithTwilio(to: string, message: string): Promise<void> {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM ?? getConfig().senderId;

  if (!accountSid || !authToken || !from) {
    throw new Error('Twilio requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM');
  }

  const body = new URLSearchParams({ To: to, From: from, Body: message });
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString('base64')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  if (!response.ok) {
    throw new Error(`Twilio rejected the SMS with status ${response.status}`);
  }
}

async function sendWithWebhook(to: string, message: string): Promise<void> {
  const webhookUrl = process.env.SMS_WEBHOOK_URL;
  const apiKey = getConfig().apiKey;
  if (!webhookUrl) {
    throw new Error('SMS_WEBHOOK_URL is required for the webhook SMS provider');
  }

  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    },
    body: JSON.stringify({ to, message, senderId: getConfig().senderId }),
  });

  if (!response.ok) {
    throw new Error(`SMS webhook rejected the message with status ${response.status}`);
  }
}

export async function sendOtpSms(to: string, otp: string): Promise<void> {
  const { provider } = getConfig();
  const message = messageForOtp(otp);

  if (provider === 'console') {
    if (process.env.NODE_ENV === 'production' && process.env.ALLOW_CONSOLE_SMS !== 'true') {
      throw new Error('Console SMS delivery is disabled in production. Set SMS_PROVIDER to twilio or webhook, or set ALLOW_CONSOLE_SMS=true in Netlify environment variables to log OTPs to Netlify Function logs.');
    }
    console.log(`[OTP] Sent code ${otp} to ${to}`);
    return;
  }

  if (provider === 'twilio') {
    await sendWithTwilio(to, message);
    return;
  }

  if (provider === 'webhook' || provider === 'custom') {
    await sendWithWebhook(to, message);
    return;
  }

  throw new Error(`Unsupported SMS_PROVIDER: ${provider || '(missing)'}`);
}
