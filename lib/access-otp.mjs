/**
 * Cloudflare Access email OTP flow for Zero Trust WARP enrollment.
 *
 * The portal host and app path are provided by the user (no hardcoded organization).
 * Session state (pre-auth cookies, nonce, kid, meta) is passed through the client
 * between /api/otp/start and /api/otp/complete — the server stays stateless.
 */

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0';

export function parsePortalUrl(portalUrl) {
  let url;
  try {
    url = new URL(portalUrl.trim());
  } catch {
    throw new Error('Enter a valid portal URL, e.g. https://your-org.cloudflareaccess.com/warp');
  }

  if (!url.hostname.endsWith('.cloudflareaccess.com')) {
    throw new Error('Portal host must be a *.cloudflareaccess.com domain.');
  }

  const appPath = url.pathname && url.pathname !== '/' ? url.pathname : '/warp';
  return {
    host: url.hostname,
    origin: url.origin,
    appPath,
  };
}

function browserHeaders(extra = {}) {
  return {
    'User-Agent': BROWSER_UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    ...extra,
  };
}

function getSetCookies(response) {
  if (typeof response.headers.getSetCookie === 'function') {
    return response.headers.getSetCookie();
  }
  const header = response.headers.get('set-cookie');
  return header ? [header] : [];
}

function applySetCookies(jar, setCookieList) {
  for (const cookie of setCookieList) {
    const semi = cookie.indexOf(';');
    const pair = (semi === -1 ? cookie : cookie.slice(0, semi)).trim();
    const eq = pair.indexOf('=');
    if (eq === -1) continue;

    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const lower = cookie.toLowerCase();
    const expired =
      value === 'deleted' ||
      value === '' ||
      lower.includes('expires=thu, 01 jan 1970') ||
      /max-age=0(\b|;)/.test(lower);

    if (expired) jar.delete(name);
    else jar.set(name, value);
  }
}

function jarToHeader(jar) {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function jarFromHeader(header) {
  const jar = new Map();
  for (const part of (header || '').split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    jar.set(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim());
  }
  return jar;
}

function extractWarpToken(html) {
  const match = html.match(/com\.cloudflare\.warp:\/\/[^/]+\/auth\?token=([A-Za-z0-9._-]+)/);
  return match ? match[1] : null;
}

/** Step 1: request an email OTP code from the Access portal. */
export async function otpStart(email, portalUrl) {
  const portal = parsePortalUrl(portalUrl);
  const jar = new Map();

  const landing = await fetch(`${portal.origin}${portal.appPath}`, {
    method: 'GET',
    redirect: 'manual',
    headers: browserHeaders(),
  });

  applySetCookies(jar, getSetCookies(landing));

  const loginLocation = landing.headers.get('location');
  if (!loginLocation || !loginLocation.includes('/cdn-cgi/access/login/')) {
    throw new Error(`Unexpected response from portal (status ${landing.status}). Check the portal URL.`);
  }

  const loginUrl = new URL(loginLocation, portal.origin);
  const kid = loginUrl.searchParams.get('kid');
  const meta = loginUrl.searchParams.get('meta');
  if (!kid || !meta) {
    throw new Error('Could not read kid/meta from the login redirect.');
  }

  const verifyUrl = loginUrl.toString().replace('/cdn-cgi/access/login/', '/cdn-cgi/access/verify-code/');
  const verifyResponse = await fetch(verifyUrl, {
    method: 'POST',
    redirect: 'manual',
    headers: browserHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: portal.origin,
      Referer: loginUrl.toString(),
      Cookie: jarToHeader(jar),
    }),
    body: new URLSearchParams({
      email,
      client_id: '',
      connector_id: '',
      connector_type: '',
      redirect_url: '',
    }).toString(),
  });

  applySetCookies(jar, getSetCookies(verifyResponse));

  const verifyLocation = verifyResponse.headers.get('location');
  if (!verifyLocation) {
    throw new Error(`verify-code did not redirect (status ${verifyResponse.status}).`);
  }

  const nonce = new URL(verifyLocation, portal.origin).searchParams.get('nonce');
  if (!nonce) {
    throw new Error('No nonce returned — the email may be outside the Access policy.');
  }

  return {
    kid,
    meta,
    nonce,
    portalHost: portal.host,
    portalOrigin: portal.origin,
    appPath: portal.appPath,
    jar: jarToHeader(jar),
  };
}

/** Step 2: submit the OTP code and extract the WARP JWT. */
export async function otpComplete({ code, nonce, kid, meta, jar, portalHost, portalOrigin, appPath }) {
  const origin = portalOrigin || `https://${portalHost}`;
  const path = appPath || '/warp';
  const cookieJar = jarFromHeader(jar);

  const verifyRef =
    `${origin}/cdn-cgi/access/verify-code/${portalHost}` +
    `?kid=${encodeURIComponent(kid)}` +
    `&meta=${encodeURIComponent(meta)}` +
    `&redirect_url=${encodeURIComponent(path)}` +
    `&nonce=${encodeURIComponent(nonce)}`;

  const callback = await fetch(`${origin}/cdn-cgi/access/callback`, {
    method: 'POST',
    redirect: 'manual',
    headers: browserHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: origin,
      Referer: verifyRef,
      Cookie: jarToHeader(cookieJar),
    }),
    body: new URLSearchParams({ code, nonce }).toString(),
  });

  applySetCookies(cookieJar, getSetCookies(callback));

  if (!cookieJar.has('CF_Authorization')) {
    throw new Error(`Wrong or expired code (callback ${callback.status}, no CF_Authorization).`);
  }

  const authLocation = callback.headers.get('location');
  if (!authLocation) {
    throw new Error('callback did not return an authorized redirect.');
  }

  const authorized = await fetch(new URL(authLocation, origin).toString(), {
    method: 'GET',
    redirect: 'manual',
    headers: browserHeaders({
      Referer: verifyRef,
      Cookie: jarToHeader(cookieJar),
    }),
  });

  applySetCookies(cookieJar, getSetCookies(authorized));

  const warpPage = await fetch(`${origin}${path}`, {
    method: 'GET',
    redirect: 'manual',
    headers: browserHeaders({
      Referer: verifyRef,
      Cookie: jarToHeader(cookieJar),
    }),
  });

  const html = await warpPage.text();
  const token = extractWarpToken(html);

  if (!token) {
    throw new Error(`Authorized, but no WARP token found on ${path} (status ${warpPage.status}).`);
  }

  return {
    token,
    authJar: jarToHeader(cookieJar),
    portalHost,
    portalOrigin: origin,
    appPath: path,
  };
}

/** Refresh a short-lived WARP JWT using an existing CF_Authorization session (~24h). */
export async function otpRefresh({ authJar, portalHost, portalOrigin, appPath }) {
  const origin = portalOrigin || `https://${portalHost}`;
  const path = appPath || '/warp';
  const cookieJar = jarFromHeader(authJar);

  if (!cookieJar.has('CF_Authorization')) {
    throw new Error('No session — please re-authenticate with an email code.');
  }

  const response = await fetch(`${origin}${path}`, {
    method: 'GET',
    redirect: 'manual',
    headers: browserHeaders({ Cookie: jarToHeader(cookieJar) }),
  });

  if (response.status === 302) {
    throw new Error('Session expired — please re-authenticate with an email code.');
  }

  const html = await response.text();
  const token = extractWarpToken(html);

  if (!token) {
    throw new Error('Could not extract a fresh token (CF_Authorization may have expired).');
  }

  return { token };
}
