/**
 * AmneziaWG I1 obfuscation packet generation.
 *
 * I1 is a valid QUIC Initial packet with a TLS ClientHello inside.
 * By default a proven working template is used; a custom SNI generates a fresh packet.
 */

const I1_TEMPLATE =
  'ce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae178f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8';

export function defaultI1() {
  return `<b 0x${I1_TEMPLATE}>`;
}

const subtle = crypto.subtle;

function asUint8Array(buffer) {
  return buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
}

function toHex(buffer) {
  return [...asUint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function concat(buffers, before = 0, after = 0) {
  const parts = buffers.map(asUint8Array);
  const total = parts.reduce((sum, part) => sum + part.byteLength, before + after);
  const result = new Uint8Array(total);
  let offset = before;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result.buffer;
}

function xor(dst, src, dstOffset, srcOffset, length) {
  const destination = asUint8Array(dst);
  const source = asUint8Array(src);
  for (let i = 0; i < length; i++) destination[dstOffset + i] ^= source[srcOffset + i];
}

function str8(data) {
  if (!data) return new ArrayBuffer(1);
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : asUint8Array(data);
  const result = new Uint8Array(input.byteLength + 1);
  new DataView(result.buffer).setUint8(0, input.byteLength);
  result.set(input, 1);
  return result.buffer;
}

function str16(data) {
  if (!data) return new ArrayBuffer(2);
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : asUint8Array(data);
  const result = new Uint8Array(input.byteLength + 2);
  new DataView(result.buffer).setUint16(0, input.byteLength, false);
  result.set(input, 2);
  return result.buffer;
}

function varint(value) {
  if (value < 0x40) return new Uint8Array([value]).buffer;
  if (value < 0x4000) {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, false);
    bytes[0] |= 0x40;
    return bytes.buffer;
  }
  if (value < 0x40000000) {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    bytes[0] |= 0x80;
    return bytes.buffer;
  }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  bytes[0] |= 0xc0;
  return bytes.buffer;
}

function varintLength(value) {
  if (value < 0x40) return 1;
  if (value < 0x4000) return 2;
  if (value < 0x40000000) return 4;
  return 8;
}

let hmacKey = null;

async function initHmacKey() {
  const salt = new Uint8Array([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
  ]);
  hmacKey = await subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function hmac(key, buffer) {
  const cryptoKey =
    key instanceof CryptoKey
      ? key
      : await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return subtle.sign('HMAC', cryptoKey, buffer);
}

async function deriveSecret(key, length, label) {
  const data = concat([str8(`tls13 ${label}`), str8(''), new Uint8Array([0x01])], 2);
  new DataView(data).setUint16(0, length, false);
  return (await hmac(key, data)).slice(0, length);
}

async function encryptPayload(key, payload, iv, aad) {
  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM', length: 128 }, false, ['encrypt']);
  return subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, cryptoKey, payload);
}

async function headerProtectionMask(key, sample) {
  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-CBC', length: 128 }, false, ['encrypt']);
  return subtle.encrypt({ name: 'AES-CBC', iv: new ArrayBuffer(16) }, cryptoKey, sample);
}

function measurePacket(dcidLen, scidLen, tokenLen, pknLen, payloadLen, padTo = 0) {
  const base = 8 + dcidLen + scidLen + tokenLen + pknLen;
  const tag = 16;
  let padding = 0;

  const totalLength = () => base + varintLength(pknLen + payloadLen + padding + tag) + pknLen + payloadLen + padding + tag;

  let overall = totalLength();
  if (overall < padTo) {
    padding = padTo - overall;
    while (padding && totalLength() > padTo) padding--;
    if (totalLength() < padTo) padding++;
    overall = totalLength();
  }

  if (pknLen + payloadLen + padding + tag < 20) {
    padding = 20 - pknLen - payloadLen - tag;
  }

  return { header: base + varintLength(pknLen + payloadLen + padding + tag), padding };
}

async function buildQuicInitial(dcid, scid, token, pkn, payload, padTo) {
  const sizes = measurePacket(
    dcid.byteLength,
    scid.byteLength,
    token.byteLength,
    pkn.byteLength,
    payload.byteLength,
    padTo
  );

  const header = concat([
    new Uint8Array([0xc0 | (pkn.byteLength - 1), 0, 0, 0, 1]),
    str8(dcid),
    str8(scid),
    str8(token),
    varint(pkn.byteLength + payload.byteLength + sizes.padding + 16),
    pkn,
  ]);

  if (!hmacKey) await initHmacKey();

  const initSecret = await hmac(hmacKey, dcid);
  const clientSecret = await deriveSecret(initSecret, 32, 'client in');
  const key = await deriveSecret(clientSecret, 16, 'quic key');
  const iv = await deriveSecret(clientSecret, 12, 'quic iv');
  const hpKey = await deriveSecret(clientSecret, 16, 'quic hp');

  xor(iv, pkn, 12 - pkn.byteLength, 0, pkn.byteLength);

  const paddedPayload = concat([payload], 0, sizes.padding);
  const encrypted = await encryptPayload(key, paddedPayload, iv, header);
  const mask = new Uint8Array(
    await headerProtectionMask(hpKey, encrypted.slice(4 - pkn.byteLength, 20 - pkn.byteLength))
  );

  mask[0] &= 0x0f;
  xor(header, mask, 0, 0, 1);
  xor(header, mask, header.byteLength - pkn.byteLength, 1, pkn.byteLength);

  return concat([header, encrypted]);
}

function cryptoFrame(data, offset = 0) {
  return concat([new Uint8Array([0x06]), varint(offset), varint(data.byteLength), data]);
}

function tlsExtension(code, content) {
  const result = concat([content], 4);
  const view = new DataView(result);
  view.setUint16(0, code, false);
  view.setUint16(2, content.byteLength, false);
  return result;
}

function tlsExtensionSni(sni) {
  const serverName = str16(sni);
  const entry = concat([serverName], 3);
  const view = new DataView(entry);
  view.setUint16(0, serverName.byteLength + 1, false);
  view.setUint8(2, 0);
  return tlsExtension(0, entry);
}

function clientHello(sni) {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const payload = concat(
    [new Uint8Array([0x03, 0x03]), random, new Uint8Array([0, 0, 0, 0]), str16(tlsExtensionSni(sni))],
    4
  );
  const view = new DataView(payload);
  view.setUint32(0, payload.byteLength - 4, false);
  view.setUint8(0, 0x01);
  return payload;
}

/** Generate a fresh QUIC Initial packet for the given SNI domain. */
export async function generateI1ForSni(sni) {
  const dcid = new Uint8Array(1);
  crypto.getRandomValues(dcid);
  const scid = new Uint8Array(0);
  const token = new Uint8Array(0);
  const packetNumber = new Uint8Array([0]);
  const hello = clientHello(sni);
  const payload = cryptoFrame(hello);
  const packet = await buildQuicInitial(dcid, scid, token, packetNumber, payload, 0);
  return `<b 0x${toHex(packet)}>`;
}

export async function resolveI1({ obfuscation, sni }) {
  if (!obfuscation) return '';
  if (sni) return generateI1ForSni(sni);
  return defaultI1();
}
