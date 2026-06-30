/**
 * HTTP server for the WARP AmneziaWG config generator.
 *
 * Serves the static UI and API routes. Run locally or deploy from a GitHub repo
 * to any Node.js host (Railway, Render, Fly.io, a VPS, etc.).
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateKeypair } from './lib/x25519.mjs';
import { computeAllowedIps } from './lib/cidr.mjs';
import { resolveI1 } from './lib/quic-i1.mjs';
import {
  registerConsumer,
  registerZeroTrust,
  revokeDevice,
  buildDeviceName,
  emailPrefixFromJwt,
} from './lib/warp-api.mjs';
import { otpStart, otpComplete, otpRefresh } from './lib/access-otp.mjs';
import {
  buildConfig,
  DEFAULT_ENDPOINT,
  DEFAULT_DNS,
  resolveEndpoint,
} from './lib/config-builder.mjs';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 3000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const text = await readBody(req);
  if (!text.trim()) {
    throw Object.assign(new Error('Empty request body.'), { status: 400 });
  }
  try {
    return JSON.parse(text);
  } catch {
    throw Object.assign(new Error('Invalid JSON body.'), { status: 400 });
  }
}

async function handleGenerate(body) {
  const zeroTrust = !!body.zeroTrust;
  const jwt = (body.token || '').trim();
  const dns = (body.dns || DEFAULT_DNS).trim();
  const include = Array.isArray(body.include) ? body.include : ['0.0.0.0/0'];
  const exclude = Array.isArray(body.exclude) ? body.exclude : [];
  const hostLabel = (body.deviceName || '').trim();
  const ipv6 = body.ipv6 !== false;
  const obfuscation = body.obfuscation !== false;

  if (zeroTrust) {
    if (!jwt || jwt.split('.').length !== 3) {
      throw Object.assign(new Error('Invalid token. A Zero Trust JWT must have three dot-separated parts.'), {
        status: 400,
      });
    }
  }

  const emailPrefix = zeroTrust ? emailPrefixFromJwt(jwt) : 'warp';
  const deviceName = buildDeviceName({ emailPrefix, hostLabel });
  const { privateKey, publicKey } = generateKeypair();

  const registration = zeroTrust
    ? await registerZeroTrust(jwt, publicKey, deviceName)
    : await registerConsumer(publicKey, deviceName);

  const config = registration.config;
  if (!config?.peers?.[0]) {
    throw Object.assign(
      new Error('Cloudflare did not return a device config. If using Zero Trust, the token may have expired.'),
      { status: 502 }
    );
  }

  const peer = config.peers[0];
  const v4 = config.interface.addresses.v4;
  const v6 = config.interface.addresses.v6;
  const address = `${v4}/32, ${v6}/128`;
  const cfToken = registration.token || '';
  const deviceId = registration.id || '';
  const accountId = registration.account?.id || '';

  let allowedIps;
  try {
    allowedIps = computeAllowedIps({
      include,
      exclude,
      includeV6: body.includeV6,
      excludeV6: body.excludeV6,
      ipv6,
    });
  } catch (error) {
    throw Object.assign(new Error(`Subnet error: ${error.message}`), { status: 400 });
  }

  let i1;
  try {
    i1 = await resolveI1({ obfuscation, sni: (body.sni || '').trim() });
  } catch (error) {
    throw Object.assign(new Error(`Failed to generate I1 for the given SNI: ${error.message}`), { status: 400 });
  }

  let endpointInfo;
  try {
    endpointInfo = resolveEndpoint({
      endpointMode: (body.endpointMode || 'default').trim(),
      body,
      peer,
    });
  } catch (error) {
    throw Object.assign(error, { status: 400 });
  }

  const refresh = cfToken && deviceId ? `${cfToken},${deviceId},${privateKey}` : '';
  const configText = buildConfig({
    privateKey,
    address,
    peerPublicKey: peer.public_key,
    dns,
    allowedIps,
    i1,
    refresh,
    deviceId,
    accountId,
    cfToken,
    endpoint: endpointInfo.endpoint,
    endpointAlts: endpointInfo.endpointAlts,
    deviceName,
    obfuscation,
  });

  return { config: configText, deviceName, deviceId, regToken: cfToken };
}

async function serveStatic(pathname) {
  const safePath = pathname === '/' ? '/index.html' : pathname;
  const filePath = join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    return new Response('Not found', { status: 404 });
  }

  try {
    const content = await readFile(filePath);
    const type = MIME_TYPES[extname(filePath)] || 'application/octet-stream';
    return new Response(content, { headers: { 'Content-Type': type } });
  } catch {
    return new Response('Not found', { status: 404 });
  }
}

async function handleRequest(request) {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const { pathname } = url;

  if (request.method === 'GET' && !pathname.startsWith('/api/')) {
    return serveStatic(pathname);
  }

  try {
    if (request.method === 'POST' && pathname === '/api/generate') {
      const body = await readJson(request);
      return jsonResponse(await handleGenerate(body));
    }

    if (request.method === 'POST' && pathname === '/api/calc') {
      const body = await readJson(request);
      const allowedIps = computeAllowedIps({
        include: Array.isArray(body.include) ? body.include : ['0.0.0.0/0'],
        exclude: Array.isArray(body.exclude) ? body.exclude : [],
        includeV6: body.includeV6,
        excludeV6: body.excludeV6,
        ipv6: body.ipv6 !== false,
      });
      const count = allowedIps.split(',').filter(Boolean).length;
      return jsonResponse({ allowedIps, count });
    }

    if (request.method === 'POST' && pathname === '/api/otp/start') {
      const body = await readJson(request);
      const email = (body.email || '').trim();
      const portalUrl = (body.portalUrl || '').trim();

      if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        return jsonResponse({ error: 'Enter a valid email address.' }, 400);
      }
      if (!portalUrl) {
        return jsonResponse({ error: 'Enter your Zero Trust portal URL.' }, 400);
      }

      return jsonResponse(await otpStart(email, portalUrl));
    }

    if (request.method === 'POST' && pathname === '/api/otp/complete') {
      const body = await readJson(request);
      const code = (body.code || '').trim();

      if (!/^\d{6}$/.test(code)) {
        return jsonResponse({ error: 'The code must be 6 digits.' }, 400);
      }
      if (!body.nonce || !body.kid || !body.meta || !body.portalHost) {
        return jsonResponse({ error: 'Session expired — request a new code.' }, 400);
      }

      return jsonResponse(await otpComplete(body));
    }

    if (request.method === 'POST' && pathname === '/api/otp/refresh') {
      const body = await readJson(request);
      if (!body.authJar || !body.portalHost) {
        return jsonResponse({ error: 'No session to refresh.' }, 400);
      }
      return jsonResponse(await otpRefresh(body));
    }

    if (request.method === 'POST' && pathname === '/api/revoke') {
      const body = await readJson(request);
      if (!body.deviceId || !body.regToken) {
        return jsonResponse({ error: 'deviceId and regToken are required.' }, 400);
      }
      return jsonResponse(await revokeDevice(body.deviceId, body.regToken, { zeroTrust: !!body.zeroTrust }));
    }

    return new Response('Not found', { status: 404 });
  } catch (error) {
    const status = error.status || 500;
    return jsonResponse({ error: error.message || String(error) }, status);
  }
}

const server = createServer((req, res) => {
  handleRequest(req)
    .then(async (response) => {
      res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
      const buffer = Buffer.from(await response.arrayBuffer());
      res.end(buffer);
    })
    .catch((error) => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
    });
});

server.listen(PORT, () => {
  console.log(`WARP AmneziaWG generator running at http://localhost:${PORT}`);
});
