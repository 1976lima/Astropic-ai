
const ALLOWED_TESTS = new Set([
  "security-headers",
  "tls-check",
  "port-inventory",
  "web-vulnerability-check"
]);

function normaliseHost(host) {
  return String(host || "").trim().toLowerCase().replace(/\.$/, "");
}

export function validateScope(scope) {
  const errors = [];

  if (!scope || typeof scope !== "object") {
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

  if (!Array.isArray(scope.allowedTargets) ||
      scope.allowedTargets.length === 0) {
    errors.push("At least one approved target is required");
  }

  if (!Array.isArray(scope.allowedTests) ||
      scope.allowedTests.length === 0) {
    errors.push("At least one permitted test is required");
  }

  if (scope.allowedTests?.some(test => !ALLOWED_TESTS.has(test))) {
    errors.push("Scope contains an unsupported test");
  }

  const expiry = Date.parse(scope.expiresAt);

  if (!Number.isFinite(expiry) || expiry <= Date.now()) {
    errors.push("Authorisation is expired or invalid");
  }

  if (Array.isArray(scope.allowedTargets)) {
    for (const target of scope.allowedTargets) {
      const host = normaliseHost(target);

      if (
        !host ||
        host.includes("/") ||
        host.includes("@") ||
        host.includes(":") ||
        host.includes("*") ||
        /\s/.test(host)
      ) {
        errors.push("Invalid or overly broad target: " + target);
      }
    }
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

  if (url.username || url.password || url.port && url.port !== "443") {
    return { allowed: false, reason: "URL credentials or non-standard port rejected" };
  }

  const hostname = normaliseHost(url.hostname);

  if (!scope.allowedTargets.map(normaliseHost).includes(hostname)) {
    return { allowed: false, reason: "Target is outside approved scope" };
  }

  const excluded = scope.excludedPaths || [];

  if (excluded.some(path =>
    typeof path === "string" &&
    (url.pathname === path ||
     url.pathname.startsWith(path.endsWith("/") ? path : path + "/"))
  )) {
    return { allowed: false, reason: "Path excluded from testing" };
  }

  return {
    allowed: true,
    reason: "Request is within the declared scope",
    target: hostname,
    testType: request.testType
  };
}
