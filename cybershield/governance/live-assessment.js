
import https from "node:https";
import tls from "node:tls";
import { isIP } from "node:net";

import {
  validateScope,
  checkRequestScope
} from "./scope-manager.js";

import { createNetworkGuard } from "./network-guard.js";
import { isPublicIp } from "./ip-classifier.js";

const TIMEOUT_MS = 7000;
const MAX_HOST_LENGTH = 253;

const REQUIRED_TESTS = [
  "security-headers",
  "tls-check"
];

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy"
];

const networkGuard = createNetworkGuard({ isPublicIp });

function serverAuthorisationScope() {
  const allowedTargets = String(
    process.env.CYBERSHIELD_ALLOWED_TARGETS || ""
  )
    .split(",")
    .map(value =>
      value.trim().toLowerCase().replace(/\.$/, "")
    )
    .filter(Boolean);

  const scope = {
    authorisationConfirmed:
      process.env.CYBERSHIELD_AUTHORIZATION_CONFIRMED === "true",

    authorisationReference:
      process.env.CYBERSHIELD_AUTHORIZATION_REFERENCE || "",

    expiresAt:
      process.env.CYBERSHIELD_AUTHORIZATION_EXPIRES_AT || "",

    allowedTargets,
    allowedTests: REQUIRED_TESTS
  };

  const validation = validateScope(scope);

  if (!validation.valid) {
    throw new Error(
      "Server authorisation scope is invalid: " +
      validation.errors.join("; ")
    );
  }

  return scope;
}

function normaliseTarget(input) {
  if (
    typeof input !== "string" ||
    !input.trim() ||
    input.length > MAX_HOST_LENGTH + 16
  ) {
    return null;
  }

  let url;

  try {
    const value = input.trim();

    url = new URL(
      /^https:\/\//i.test(value)
        ? value
        : `https://${value}`
    );
  } catch {
    return null;
  }

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    return null;
  }

  const hostname = url.hostname
    .toLowerCase()
    .replace(/\.$/, "");

  if (
    !hostname ||
    hostname.length > MAX_HOST_LENGTH ||
    isIP(hostname) !== 0 ||
    !hostname.includes(".") ||
    !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(hostname)
  ) {
    return null;
  }

  return hostname;
}

function checkAuthorisedScope(host) {
  const scope = serverAuthorisationScope();
  const url = `https://${host}/`;

  for (const testType of REQUIRED_TESTS) {
    const decision = checkRequestScope(scope, {
      url,
      testType
    });

    if (!decision.allowed) {
      throw new Error(
        decision.reason ||
        "Assessment is outside the authorised scope."
      );
    }
  }

  return scope;
}

export function validateAssessmentRequest(body) {
  const target = normaliseTarget(body?.target);

  if (!target) {
    return {
      valid: false,
      error:
        "Enter a valid HTTPS hostname without a path, credentials or port."
    };
  }

  try {
    checkAuthorisedScope(target);

    return {
      valid: true,
      target
    };
  } catch (error) {
    return {
      valid: false,
      error: error.message
    };
  }
}

function pinnedLookup(addresses) {
  const selected = addresses[0];

  return (_hostname, options, callback) => {
    if (options?.all) {
      callback(
        null,
        addresses.map(item => ({
          address: item.address,
          family: item.family
        }))
      );
      return;
    }

    callback(
      null,
      selected.address,
      selected.family
    );
  };
}

function requestHead(host, addresses) {
  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        protocol: "https:",
        hostname: host,
        port: 443,
        method: "HEAD",
        path: "/",
        servername: host,

        // TLS validity is inspected separately.
        rejectUnauthorized: false,

        timeout: TIMEOUT_MS,
        maxHeaderSize: 16 * 1024,
        lookup: pinnedLookup(addresses),

        headers: {
          "User-Agent": "AstropicAI-CyberShield/1.0",
          "Accept": "*/*",
          "Connection": "close"
        }
      },

      response => {
        const headers = {};

        for (const name of SECURITY_HEADERS) {
          const value = response.headers[name];

          if (typeof value === "string") {
            headers[name] = value.slice(0, 2048);
          } else if (Array.isArray(value)) {
            headers[name] = value
              .join(", ")
              .slice(0, 2048);
          }
        }

        const result = {
          statusCode: response.statusCode || 0,
          headers,
          locationPresent: Boolean(response.headers.location),
          tlsAuthorised: response.socket?.authorized === true,
          tlsAuthorizationError:
            response.socket?.authorizationError || null
        };

        response.destroy();
        resolve(result);
      }
    );

    request.on("timeout", () => {
      request.destroy(
        new Error("The HTTPS request timed out.")
      );
    });

    request.on("error", reject);
    request.end();
  });
}

function inspectCertificate(host, addresses) {
  return new Promise((resolve, reject) => {
    const selected = addresses[0];

    const socket = tls.connect({
      host: selected.address,
      family: selected.family,
      port: 443,
      servername: host,
      rejectUnauthorized: false,
      timeout: TIMEOUT_MS
    });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();

      const validTo = certificate.valid_to
        ? new Date(certificate.valid_to)
        : null;

      const validDate =
        validTo &&
        Number.isFinite(validTo.getTime());

      const daysUntilExpiry = validDate
        ? Math.floor(
            (validTo.getTime() - Date.now()) / 86400000
          )
        : null;

      const authorised = socket.authorized === true;

      const result = {
        checked: true,
        valid: authorised,
        authorized: authorised,
        authorizationError:
          socket.authorizationError || null,

        validTo: validDate
          ? validTo.toISOString()
          : null,

        daysUntilExpiry,

        subject:
          certificate.subject?.CN || null,

        issuer:
          certificate.issuer?.O ||
          certificate.issuer?.CN ||
          null,

        protocol:
          socket.getProtocol() || null
      };

      socket.end();
      resolve(result);
    });

    socket.setTimeout(TIMEOUT_MS, () => {
      socket.destroy(
        new Error("The TLS handshake timed out.")
      );
    });

    socket.once("error", reject);
  });
}

export async function collectPassiveEvidence(target) {
  const host = normaliseTarget(target);

  if (!host) {
    throw new Error("Invalid assessment target.");
  }

  const scope = checkAuthorisedScope(host);
  const url = `https://${host}/`;

  const destination =
    await networkGuard.validateDestination(scope, url);

  if (
    !destination ||
    !Array.isArray(destination.addresses) ||
    destination.addresses.length === 0
  ) {
    throw new Error(
      destination?.reason ||
      "DNS and public-IP validation failed."
    );
  }

  const addresses = destination.addresses.map(item => {
    const address =
      typeof item === "string"
        ? item
        : item?.address;

    return {
      address,
      family: isIP(address)
    };
  });

  if (
    addresses.some(item =>
      !item.address ||
      item.family === 0 ||
      !isPublicIp(item.address)
    )
  ) {
    throw new Error(
      "A non-public or invalid IP address was detected."
    );
  }

  const [http, certificate] = await Promise.all([
    requestHead(host, addresses),
    inspectCertificate(host, addresses)
  ]);

  return {
    target: host,

    collectionMethod:
      "Authorised, DNS-validated, IP-pinned passive HTTPS HEAD and TLS inspection",

    collectedAt: new Date().toISOString(),

    dns: {
      addresses: addresses.map(item => item.address),
      validatedAt:
        destination.timestamp ||
        destination.validatedAt ||
        null
    },

    // The engine reads evidence.headers.
    headers: http.headers,

    http,

    // The engine reads evidence.tls.checked and evidence.tls.valid.
    tls: certificate,

    limits: {
      redirectsFollowed: false,
      requestMethod: "HEAD",
      responseBodyRead: false,
      timeoutMs: TIMEOUT_MS,
      scopeTests: REQUIRED_TESTS
    }
  };
}
