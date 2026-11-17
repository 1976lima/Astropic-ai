
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const MAX_REDIRECTS = 5;

function normaliseHost(host) {
  return String(host || "").trim().toLowerCase().replace(/\.$/, "");
}

function isValidHostname(host) {
  if (!host || host.length > 253) return false;
  if (isIP(host)) return false;

  const labels = host.split(".");

  return labels.every(label =>
    label.length > 0 &&
    label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

export function createNetworkGuard({
  isPublicIp
} = {}) {
  if (typeof isPublicIp !== "function") {
    throw new Error("Trusted IP classification is required");
  }

  async function validateDestination(scope, input) {
    let url;

    try {
      url = new URL(input);
    } catch {
      return { allowed: false, reason: "Invalid URL" };
    }

    if (url.protocol !== "https:") {
      return { allowed: false, reason: "HTTPS required" };
    }

    if (url.username || url.password || url.port) {
      return {
        allowed: false,
        reason: "Credentials and custom ports rejected"
      };
    }

    const host = normaliseHost(url.hostname);

    if (!isValidHostname(host)) {
      return {
        allowed: false,
        reason: "Invalid or unsupported hostname"
      };
    }

    const approved = (scope?.allowedTargets || [])
      .map(normaliseHost);

    if (!approved.includes(host)) {
      return {
        allowed: false,
        reason: "Hostname outside approved scope"
      };
    }

    let records;

    try {
      records = await lookup(host, {
        all: true,
        verbatim: true
      });
    } catch {
      return {
        allowed: false,
        reason: "DNS resolution failed"
      };
    }

    if (!records.length) {
      return {
        allowed: false,
        reason: "No DNS addresses found"
      };
    }

    for (const record of records) {
      if (
        !isIP(record.address) ||
        isPublicIp(record.address) !== true
      ) {
        return {
          allowed: false,
          reason: "Non-public or unverified network address"
        };
      }
    }

    return {
      allowed: true,
      hostname: host,
      addresses: records.map(record => record.address),
      validatedAt: new Date().toISOString()
    };
  }

  async function validateRedirectChain(scope, initialUrl, redirectUrls) {
    if (!Array.isArray(redirectUrls)) {
      return { allowed: false, reason: "Invalid redirect chain" };
    }

    if (redirectUrls.length > MAX_REDIRECTS) {
      return { allowed: false, reason: "Redirect limit exceeded" };
    }

    const chain = [initialUrl, ...redirectUrls];
    const validated = [];

    for (const destination of chain) {
      const result = await validateDestination(scope, destination);

      if (!result.allowed) {
        return {
          allowed: false,
          reason: "Redirect destination rejected",
          detail: result.reason,
          validated
        };
      }

      validated.push(result);
    }

    return {
      allowed: true,
      validated
    };
  }

  return Object.freeze({
    validateDestination,
    validateRedirectChain
  });
}
