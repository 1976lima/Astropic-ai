
import { isIP } from "node:net";

const IPV4_BLOCKED = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
  ["255.255.255.255", 32]
];

function ipv4Number(ip) {
  if (isIP(ip) !== 4) return null;

  return ip.split(".").reduce(
    (n, part) => n * 256 + Number(part),
    0
  );
}

function inIPv4Range(ip, network, prefix) {
  const value = ipv4Number(ip);
  const base = ipv4Number(network);

  if (value === null || base === null) return false;

  const mask = prefix === 0
    ? 0
    : (0xffffffff << (32 - prefix)) >>> 0;

  return ((value & mask) >>> 0) ===
    ((base & mask) >>> 0);
}

function expandIPv6(ip) {
  if (isIP(ip) !== 6 || ip.includes("%")) {
    return null;
  }

  let address = ip.toLowerCase();

  if (address.includes(".")) {
    const lastColon = address.lastIndexOf(":");
    const ipv4 = address.slice(lastColon + 1);
    const number = ipv4Number(ipv4);

    if (number === null) return null;

    const high = ((number >>> 16) & 0xffff).toString(16);
    const low = (number & 0xffff).toString(16);

    address =
      address.slice(0, lastColon + 1) +
      high + ":" + low;
  }

  const halves = address.split("::");

  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(":") : [];
  const right =
    halves.length === 2 && halves[1]
      ? halves[1].split(":")
      : [];

  const missing = 8 - left.length - right.length;

  if (
    (halves.length === 1 && missing !== 0) ||
    (halves.length === 2 && missing < 1)
  ) {
    return null;
  }

  const words = [
    ...left,
    ...Array(missing).fill("0"),
    ...right
  ];

  if (
    words.length !== 8 ||
    words.some(w => !/^[0-9a-f]{1,4}$/.test(w))
  ) {
    return null;
  }

  return words.map(w => parseInt(w, 16));
}

function prefixMatch(words, network, prefix) {
  let remaining = prefix;

  for (let i = 0; i < words.length; i++) {
    if (remaining <= 0) return true;

    const bits = Math.min(16, remaining);
    const mask = (0xffff << (16 - bits)) & 0xffff;

    if ((words[i] & mask) !== (network[i] & mask)) {
      return false;
    }

    remaining -= bits;
  }

  return remaining <= 0;
}

function ipv6ToIPv4(words) {
  return [
    (words[6] >> 8) & 255,
    words[6] & 255,
    (words[7] >> 8) & 255,
    words[7] & 255
  ].join(".");
}

export function classifyIp(input) {
  if (typeof input !== "string") {
    return { valid: false, category: "invalid" };
  }

  const ip = input.trim();

  if (!ip || ip.length > 45 || ip.includes("%")) {
    return { valid: false, category: "invalid" };
  }

  const version = isIP(ip);

  if (version === 4) {
    const blocked = IPV4_BLOCKED.some(
      ([network, prefix]) =>
        inIPv4Range(ip, network, prefix)
    );

    return {
      valid: true,
      address: ip,
      version: 4,
      category: blocked ? "non-public" : "public",
      isPublic: !blocked
    };
  }

  if (version === 6) {
    const words = expandIPv6(ip);

    if (!words) {
      return { valid: false, category: "invalid" };
    }

    // Detect IPv4-mapped IPv6 addresses.
    const mapped =
      words.slice(0, 5).every(w => w === 0) &&
      words[5] === 0xffff;

    if (mapped) {
      const embedded = ipv6ToIPv4(words);
      const result = classifyIp(embedded);

      return {
        ...result,
        address: ip,
        version: 6,
        mappedIPv4: embedded
      };
    }

    // Only consider global-unicast IPv6 space.
    const globalUnicast = prefixMatch(
      words,
      [0x2000, 0, 0, 0, 0, 0, 0, 0],
      3
    );

    // Exclude special-purpose and transition ranges.
    const excluded = [
      [[0x2001, 0, 0, 0, 0, 0, 0, 0], 23],
      [[0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32],
      [[0x2002, 0, 0, 0, 0, 0, 0, 0], 16],
      [[0x3fff, 0, 0, 0, 0, 0, 0, 0], 20]
    ].some(([network, prefix]) =>
      prefixMatch(words, network, prefix)
    );

    const isPublic = globalUnicast && !excluded;

    return {
      valid: true,
      address: ip,
      version: 6,
      category: isPublic ? "public" : "non-public",
      isPublic
    };
  }

  return {
    valid: false,
    category: "invalid"
  };
}

export function isPublicIp(input) {
  const result = classifyIp(input);

  return result.valid && result.isPublic;
}
