
const ALLOWED_TESTS = new Set([
  "security-headers",
  "tls-check",
  "port-inventory",
  "web-vulnerability-check"
]);

function normaliseHost(host) {
  if (typeof host !== "string") return "";
  return host.trim().toLowerCase().replace(/\.$/, "");
}

function canonicalPath(path) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    return null;
  }

  let decoded;

  try {
    decoded = decodeURIComponent(path);
  } catch {
    return null;
  }

  if (
    decoded.includes("\\") ||
    decoded.includes("\0")
  ) {
    return null;
  }

  const segments = [];

  for (const segment of decoded.split("/")) {
    if (!segment || segment === ".") continue;

    if (segment === "..") {
      segments.pop();
    } else {
      segments.push(segment);
    }
  }

  return "/" + segments.join("/");
}

export function validateScope(scope) {
  const errors = [];

  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    return { valid: false, errors: ["Scope is required"] };
  }

  if (scope.authorisationConfirmed !== true) {
    errors.push("Explicit authorisation is required");
  }

  if (
    typeof scope.authorisationReference !== "string" ||
    !scope.authorisationReference.trim()
  ) {
    errors.push("Authorisation reference is required");
  }

  if (
    !Array.isArray(scope.allowedTargets) ||
    scope.allowedTargets.length === 0
  ) {
    errors.push("At least one approved target is required");
  } else {
    for (const target of scope.allowedTargets) {
      if (typeof target !== "string") {
        errors.push("Target entries must be strings");
        continue;
      }

      const host = normaliseHost(target);

      if (
        !host ||
        host.length > 253 ||
        host.includes("/") ||
        host.includes("@") ||
        host.includes(":") ||
        host.includes("*") ||
        /\s/.test(host) ||
        !host.split(".").every(label =>
          label.length > 0 &&
          label.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
        )
      ) {
        errors.push("Invalid or overly broad target: " + target);
      }
    }
  }

  if (
    !Array.isArray(scope.allowedTests) ||
    scope.allowedTests.length === 0
  ) {
    errors.push("At least one permitted test is required");
  } else if (
    scope.allowedTests.some(test =>
      typeof test !== "string" || !ALLOWED_TESTS.has(test)
    )
  ) {
    errors.push("Scope contains an unsupported test");
  }

  if (
    scope.excludedPaths !== undefined &&
    !Array.isArray(scope.excludedPaths)
  ) {
    errors.push("Excluded paths must be an array");
  } else if (Array.isArray(scope.excludedPaths)) {
    for (const path of scope.excludedPaths) {
      if (canonicalPath(path) === null) {
        errors.push("Invalid excluded path");
      }
    }
  }

  if (
    typeof scope.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(scope.expiresAt)) ||
    Date.parse(scope.expiresAt) <= Date.now()
  ) {
    errors.push("Authorisation is expired or invalid");
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

export function checkRequestScope(scope, request) {
  const validation = validateScope(scope);

  if (!validation.valid) {
    return {
      allowed: false,
      reason: "Invalid authorisation scope",
      errors: validation.errors
    };
  }

  if (!request || typeof request.url !== "string") {
    return { allowed: false, reason: "Invalid request URL" };
  }

  if (!scope.allowedTests.includes(request.testType)) {
    return { allowed: false, reason: "Test not authorised" };
  }

  let url;

  try {
    url = new URL(request.url);
  } catch {
    return { allowed: false, reason: "Invalid URL" };
  }

  if (url.protocol !== "https:") {
    return { allowed: false, reason: "HTTPS required" };
  }

  if (
    url.username ||
    url.password ||
    (url.port && url.port !== "443")
  ) {
    return {
      allowed: false,
      reason: "URL credentials or non-standard port rejected"
    };
  }

  const hostname = normaliseHost(url.hostname);

  if (!scope.allowedTargets.map(normaliseHost).includes(hostname)) {
    return {
      allowed: false,
      reason: "Target is outside approved scope"
    };
  }

  const requestPath = canonicalPath(url.pathname);

  if (requestPath === null) {
    return {
      allowed: false,
      reason: "Invalid or ambiguous request path"
    };
  }

  for (const excluded of scope.excludedPaths || []) {
    const excludedPath = canonicalPath(excluded);

    if (
      requestPath === excludedPath ||
      requestPath.startsWith(
        excludedPath.endsWith("/")
          ? excludedPath
          : excludedPath + "/"
      )
    ) {
      return {
        allowed: false,
        reason: "Path excluded from testing"
      };
    }
  }

  return {
    allowed: true,
    reason: "Request is within the declared scope",
    target: hostname,
    testType: request.testType
  };
}
