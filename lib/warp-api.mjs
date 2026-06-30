/**
 * Cloudflare WARP device registration.
 *
 * Consumer mode (default): register without JWT, then enable WARP via PATCH.
 * Zero Trust mode: register with a CF-Access-Jwt-Assertion header.
 */

const CONSUMER_API = 'https://api.cloudflareclient.com/v0i1909051800';
const ZERO_TRUST_API = 'https://api.cloudflareclient.com/v0a2483';

const CONSUMER_HEADERS = {
  'User-Agent': 'okhttp/3.12.1',
  'Content-Type': 'application/json',
};

const ZERO_TRUST_HEADERS = {
  'User-Agent': '1.1.1.1/6.81',
  'CF-Client-Version': 'a-6.81-2410012252.0',
  Accept: 'application/json; charset=UTF-8',
  'Content-Type': 'application/json',
};

async function readError(response) {
  const text = await response.text();
  return text.slice(0, 300);
}

/** Register a free consumer WARP device (no Zero Trust). */
export async function registerConsumer(publicKey, deviceName = '') {
  const tos = new Date().toISOString();

  const registerResponse = await fetch(`${CONSUMER_API}/reg`, {
    method: 'POST',
    headers: CONSUMER_HEADERS,
    body: JSON.stringify({
      install_id: '',
      tos,
      key: publicKey,
      fcm_token: '',
      type: 'ios',
      locale: 'en_US',
    }),
  });

  if (!registerResponse.ok) {
    throw new Error(`Cloudflare registration failed (${registerResponse.status}): ${await readError(registerResponse)}`);
  }

  const registration = await registerResponse.json();
  const id = registration.id ?? registration.result?.id;
  const token = registration.token ?? registration.result?.token;

  if (!id || !token) {
    throw new Error('Cloudflare did not return device id/token.');
  }

  const patchResponse = await fetch(`${CONSUMER_API}/reg/${id}`, {
    method: 'PATCH',
    headers: {
      ...CONSUMER_HEADERS,
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ warp_enabled: true }),
  });

  if (!patchResponse.ok) {
    throw new Error(`Cloudflare WARP enable failed (${patchResponse.status}): ${await readError(patchResponse)}`);
  }

  const enabled = await patchResponse.json();
  const result = enabled.result ?? enabled;

  if (deviceName) {
    try {
      await fetch(`${CONSUMER_API}/reg/${id}`, {
        method: 'PATCH',
        headers: {
          ...CONSUMER_HEADERS,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ name: deviceName, model: deviceName }),
      });
    } catch {
      // Best-effort rename; config generation should still succeed.
    }
  }

  return {
    id,
    token,
    account: result.account,
    config: result.config,
  };
}

/** Register a Zero Trust WARP device using an Access JWT. */
export async function registerZeroTrust(jwt, publicKey, deviceName = '') {
  const response = await fetch(`${ZERO_TRUST_API}/reg`, {
    method: 'POST',
    headers: {
      ...ZERO_TRUST_HEADERS,
      'CF-Access-Jwt-Assertion': jwt,
    },
    body: JSON.stringify({
      key: publicKey,
      install_id: '',
      fcm_token: '',
      model: deviceName || 'warp-generator',
      serial_number: '',
      name: deviceName || '',
      locale: 'en_US',
    }),
  });

  if (!response.ok) {
    throw new Error(`Cloudflare Zero Trust registration failed (${response.status}): ${await readError(response)}`);
  }

  const registration = await response.json();

  if (deviceName && registration.id && registration.token) {
    try {
      await fetch(`${ZERO_TRUST_API}/reg/${registration.id}`, {
        method: 'PATCH',
        headers: {
          ...ZERO_TRUST_HEADERS,
          Authorization: `Bearer ${registration.token}`,
        },
        body: JSON.stringify({ name: deviceName, model: deviceName }),
      });
    } catch {
      // Best-effort rename.
    }
  }

  return registration;
}

/** Remove a device registration (works for both consumer and Zero Trust tokens). */
export async function revokeDevice(deviceId, regToken, { zeroTrust = false } = {}) {
  const base = zeroTrust ? ZERO_TRUST_API : CONSUMER_API;
  const headers = zeroTrust
    ? { ...ZERO_TRUST_HEADERS, Authorization: `Bearer ${regToken}` }
    : { ...CONSUMER_HEADERS, Authorization: `Bearer ${regToken}` };

  const response = await fetch(`${base}/reg/${deviceId}`, {
    method: 'DELETE',
    headers,
  });

  if (!response.ok) {
    throw new Error(`Revoke failed (${response.status}): ${await readError(response)}`);
  }

  return { ok: true };
}

export function buildDeviceName({ emailPrefix, hostLabel }) {
  const prefix = emailPrefix || 'warp';
  const host = hostLabel.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  const random = Array.from(crypto.getRandomValues(new Uint8Array(3)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 5);

  return host ? `${prefix}-${host}-${random}` : `${prefix}-${random}`;
}

export function emailPrefixFromJwt(jwt) {
  try {
    const payload = JSON.parse(
      Buffer.from(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    );
    if (payload.email) return payload.email.split('@')[0];
  } catch {
    // Ignore malformed JWT payloads.
  }
  return 'warp';
}
