/**
 * IPv4/IPv6 CIDR calculator for WireGuard AllowedIPs.
 * Merges include ranges and subtracts exclude ranges.
 */

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((x) => isNaN(x) || x < 0 || x > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parseIpv4Cidr(cidr) {
  const [ip, prefixStr] = cidr.trim().split('/');
  const prefix = prefixStr === undefined ? 32 : parseInt(prefixStr, 10);
  if (prefix < 0 || prefix > 32) throw new Error(`Invalid IPv4 prefix: ${cidr}`);

  const base = ipv4ToInt(ip);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  const size = prefix === 0 ? 0x100000000 : 2 ** (32 - prefix);
  return { start: network, end: network + size - 1 };
}

function rangeToIpv4Cidrs(start, end) {
  const result = [];
  let current = start;

  while (current <= end) {
    let align = 32;
    if (current !== 0) {
      align = 0;
      let value = current;
      while ((value & 1) === 0 && align < 32) {
        value >>>= 1;
        align++;
      }
    }

    let bits = align;
    const remaining = end - current + 1;
    while (bits > 0 && 2 ** bits > remaining) bits--;

    result.push(`${intToIpv4(current)}/${32 - bits}`);
    current += 2 ** bits;
    if (current > 0xffffffff) break;
  }

  return result;
}

function subtractIpv4Ranges(includeStart, includeEnd, excludes) {
  let segments = [{ start: includeStart, end: includeEnd }];

  for (const exclude of excludes) {
    const next = [];
    for (const segment of segments) {
      if (exclude.end < segment.start || exclude.start > segment.end) {
        next.push(segment);
        continue;
      }
      if (exclude.start > segment.start) {
        next.push({ start: segment.start, end: exclude.start - 1 });
      }
      if (exclude.end < segment.end) {
        next.push({ start: exclude.end + 1, end: segment.end });
      }
    }
    segments = next;
  }

  const cidrs = [];
  for (const segment of segments) {
    cidrs.push(...rangeToIpv4Cidrs(segment.start, segment.end));
  }
  return cidrs;
}

export function computeAllowedIpv4(includeCidrs, excludeCidrs) {
  const includes = includeCidrs.map(parseIpv4Cidr).sort((a, b) => a.start - b.start);
  const merged = [];

  for (const range of includes) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end + 1) {
      last.end = Math.max(last.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }

  const excludes = excludeCidrs.map(parseIpv4Cidr).sort((a, b) => a.start - b.start);
  let result = [];

  for (const include of merged) {
    const relevant = excludes.filter((e) => e.end >= include.start && e.start <= include.end);
    result = result.concat(subtractIpv4Ranges(include.start, include.end, relevant));
  }

  return result;
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

function expandIpv6(addr) {
  const halves = addr.split('::');
  let groups;

  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const fill = 8 - left.length - right.length;
    groups = [...left, ...Array(fill).fill('0'), ...right];
  } else {
    groups = addr.split(':');
  }

  return groups.map((g) => g.padStart(4, '0')).slice(0, 8);
}

function ipv6ToBigInt(addr) {
  const groups = expandIpv6(addr);
  let value = 0n;
  for (const hex of groups) value = (value << 16n) | BigInt(parseInt(hex, 16));
  return value;
}

function bigIntToIpv6(value) {
  const groups = [];
  for (let i = 0; i < 8; i++) {
    groups.unshift((value & 0xffffn).toString(16));
    value >>= 16n;
  }

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (curStart === -1) curStart = i;
      curLen = i - curStart + 1;
    } else {
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
      curStart = -1;
      curLen = 0;
    }
  }

  if (curLen > bestLen) {
    bestStart = curStart;
    bestLen = curLen;
  }

  if (bestLen >= 2) {
    const left = groups.slice(0, bestStart).join(':');
    const right = groups.slice(bestStart + bestLen).join(':');
    return `${left || ''}::${right || ''}`;
  }

  return groups.join(':');
}

const MASK_128 = (1n << 128n) - 1n;

function parseIpv6Cidr(cidr) {
  const [ip, prefixStr] = cidr.trim().split('/');
  const prefix = prefixStr !== undefined ? parseInt(prefixStr, 10) : 128;
  if (prefix < 0 || prefix > 128) throw new Error(`Invalid IPv6 prefix: ${cidr}`);

  const base = ipv6ToBigInt(ip);
  const mask = prefix === 0 ? 0n : (MASK_128 << BigInt(128 - prefix)) & MASK_128;
  const network = base & mask;
  const size = 1n << BigInt(128 - prefix);
  return { start: network, end: network + size - 1n };
}

function rangeToIpv6Cidrs(start, end) {
  const result = [];
  let current = start;

  while (current <= end) {
    let align = 128;
    if (current !== 0n) {
      align = 0;
      let value = current;
      while ((value & 1n) === 0n && align < 128) {
        value >>= 1n;
        align++;
      }
    }

    let bits = align;
    const remaining = end - current + 1n;
    while (bits > 0 && (1n << BigInt(bits)) > remaining) bits--;

    result.push(`${bigIntToIpv6(current)}/${128 - bits}`);
    current += 1n << BigInt(bits);
    if (current > MASK_128) break;
  }

  return result;
}

function subtractIpv6Ranges(includeStart, includeEnd, excludes) {
  let segments = [{ start: includeStart, end: includeEnd }];

  for (const exclude of excludes) {
    const next = [];
    for (const segment of segments) {
      if (exclude.end < segment.start || exclude.start > segment.end) {
        next.push(segment);
        continue;
      }
      if (exclude.start > segment.start) {
        next.push({ start: segment.start, end: exclude.start - 1n });
      }
      if (exclude.end < segment.end) {
        next.push({ start: exclude.end + 1n, end: segment.end });
      }
    }
    segments = next;
  }

  const cidrs = [];
  for (const segment of segments) {
    cidrs.push(...rangeToIpv6Cidrs(segment.start, segment.end));
  }
  return cidrs;
}

export function computeAllowedIpv6(includeCidrs, excludeCidrs) {
  const includes = includeCidrs.map(parseIpv6Cidr).sort((a, b) =>
    a.start < b.start ? -1 : a.start > b.start ? 1 : 0
  );
  const merged = [];

  for (const range of includes) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end + 1n) {
      if (range.end > last.end) last.end = range.end;
    } else {
      merged.push({ start: range.start, end: range.end });
    }
  }

  const excludes = excludeCidrs.map(parseIpv6Cidr).sort((a, b) =>
    a.start < b.start ? -1 : 1
  );
  let result = [];

  for (const include of merged) {
    const relevant = excludes.filter((e) => e.end >= include.start && e.start <= include.end);
    result = result.concat(subtractIpv6Ranges(include.start, include.end, relevant));
  }

  return result;
}

export function computeAllowedIps({ include, exclude, includeV6, excludeV6, ipv6 }) {
  const cidrs = computeAllowedIpv4(include, exclude);

  if (ipv6) {
    const v6Include = includeV6?.length ? includeV6 : ['::/0'];
    const v6Exclude = excludeV6 ?? [];
    if (v6Exclude.length) {
      cidrs.push(...computeAllowedIpv6(v6Include, v6Exclude));
    } else {
      cidrs.push(...v6Include);
    }
  }

  return cidrs.join(', ');
}
