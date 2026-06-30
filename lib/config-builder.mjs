/**
 * AmneziaWG / WireGuard config file builder.
 */

export const DEFAULT_ENDPOINT = '162.159.193.1:2408';
export const DEFAULT_DNS = '1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001';

export const AWG_PARAMS = {
  MTU: 1280,
  Jc: 4,
  Jmin: 40,
  Jmax: 70,
  S1: 0,
  S2: 0,
  S3: 0,
  S4: 0,
  H1: 1,
  H2: 2,
  H3: 3,
  H4: 4,
};

export const NAT64_PREFIXES = {
  CH: '2a14:7583:f764:64::',
  DE: '2001:67c:2960:6464::',
  NL: '2a02:898:146:64::',
  FI: '2001:67c:2b0:db32::',
  US1: '2602:fc59:11:64::',
  US2: '2602:fc59:b0:64::',
  HK: '2600:70ff:ac2c:64::',
};

export function nat64Embed(prefix, ipv4) {
  return `${prefix}${ipv4}`;
}

export function buildConfig({
  privateKey,
  address,
  peerPublicKey,
  dns = DEFAULT_DNS,
  allowedIps,
  i1,
  refresh,
  deviceId,
  accountId,
  cfToken,
  endpoint,
  deviceName,
  obfuscation,
  endpointAlts = [],
}) {
  const lines = [];

  if (deviceName) lines.push(`# Device name: ${deviceName}`);

  lines.push('[Interface]');
  lines.push(`PrivateKey = ${privateKey}`);
  lines.push(`Address = ${address}`);
  lines.push(`DNS = ${dns}`);
  lines.push(`MTU = ${AWG_PARAMS.MTU}`);

  if (obfuscation) {
    lines.push(`Jc = ${AWG_PARAMS.Jc}`);
    lines.push(`Jmin = ${AWG_PARAMS.Jmin}`);
    lines.push(`Jmax = ${AWG_PARAMS.Jmax}`);
    lines.push(`S1 = ${AWG_PARAMS.S1}`);
    lines.push(`S2 = ${AWG_PARAMS.S2}`);
    lines.push(`S3 = ${AWG_PARAMS.S3}`);
    lines.push(`S4 = ${AWG_PARAMS.S4}`);
    lines.push(`H1 = ${AWG_PARAMS.H1}`);
    lines.push(`H2 = ${AWG_PARAMS.H2}`);
    lines.push(`H3 = ${AWG_PARAMS.H3}`);
    lines.push(`H4 = ${AWG_PARAMS.H4}`);
    lines.push(`I1 = ${i1}`);
  }

  if (refresh) {
    lines.push('');
    lines.push('# To refresh this config later, run warp.sh with the -R option:');
    lines.push(`#   ./warp.sh -R '${refresh}'`);
    lines.push('# (format: token,device_id,private_key)');
  }

  if (deviceId) lines.push(`#CFDeviceId = ${deviceId}`);
  if (accountId) lines.push(`#CFAccountId = ${accountId}`);
  if (cfToken) lines.push(`#CFToken = ${cfToken}`);

  lines.push('');
  lines.push('[Peer]');
  lines.push(`PublicKey = ${peerPublicKey}`);
  lines.push(`AllowedIPs = ${allowedIps}`);
  lines.push(`Endpoint = ${endpoint || DEFAULT_ENDPOINT}`);

  for (const alt of endpointAlts) {
    if (alt) lines.push(`#Endpoint = ${alt}`);
  }

  lines.push('PersistentKeepalive = 25');
  return lines.join('\n');
}

export function resolveEndpoint({ endpointMode, body, peer, defaultPort }) {
  let ipv4Endpoint = (body.endpoint || '').trim();
  if (ipv4Endpoint) {
    const valid = /^\[?[0-9a-zA-Z.:_-]+\]?:\d{1,5}$/.test(ipv4Endpoint);
    const port = parseInt(ipv4Endpoint.split(':').pop(), 10);
    if (!valid || Number.isNaN(port) || port < 1 || port > 65535) {
      throw new Error('Invalid endpoint. Use host:port, e.g. 162.159.193.1:2408');
    }
  } else {
    ipv4Endpoint = DEFAULT_ENDPOINT;
  }

  let ipv6Endpoint = '';
  const peerV6 = peer?.endpoint?.v6 || '';
  if (peerV6) {
    const match = peerV6.match(/^\[?([0-9a-fA-F:]+)\]?(?::(\d+))?$/);
    if (match) {
      const port = match[2] && match[2] !== '0' ? match[2] : defaultPort;
      ipv6Endpoint = `[${match[1]}]:${port}`;
    }
  }

  const endpointAlts = [];
  let endpoint;

  if (endpointMode === 'nat64') {
    const country = (body.nat64Country || '').trim();
    const prefix = NAT64_PREFIXES[country];
    if (!prefix) throw new Error('Select a valid NAT64 prefix.');

    const [ipv4Part, portPart] = ipv4Endpoint.split(':');
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ipv4Part)) {
      throw new Error('NAT64 mode needs a numeric IPv4 endpoint to embed, e.g. 162.159.193.1:2408');
    }

    const port = portPart || defaultPort;
    endpoint = `[${nat64Embed(prefix, ipv4Part)}]:${port}`;
    endpointAlts.push(ipv4Endpoint);
    if (ipv6Endpoint) endpointAlts.push(ipv6Endpoint);
  } else if (endpointMode === 'ipv6') {
    if (!ipv6Endpoint) {
      throw new Error('No IPv6 endpoint was returned for this peer by Cloudflare.');
    }
    endpoint = ipv6Endpoint;
    endpointAlts.push(ipv4Endpoint);
  } else {
    endpoint = ipv4Endpoint;
    if (ipv6Endpoint) endpointAlts.push(ipv6Endpoint);
  }

  return { endpoint, endpointAlts };
}
