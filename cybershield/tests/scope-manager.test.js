
import test from "node:test";
import assert from "node:assert/strict";

import {
  validateScope,
  checkRequestScope
} from "../governance/scope-manager.js";

function validScope(overrides = {}) {
  return {
    authorisationConfirmed: true,
    authorisationReference: "TEST-AUTH-001",
    allowedTargets: ["example.com"],
    allowedTests: ["security-headers", "tls-check"],
    excludedPaths: ["/private", "/admin"],
    expiresAt: "2099-12-31T23:59:59.000Z",
    ...overrides
  };
}

test("accepts a valid authorisation scope", () => {
  const result = validateScope(validScope());
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("rejects missing authorisation", () => {
  const result = validateScope(
    validScope({ authorisationConfirmed: false })
  );
  assert.equal(result.valid, false);
});

test("rejects missing authorisation reference", () => {
  const result = validateScope(
    validScope({ authorisationReference: "" })
  );
  assert.equal(result.valid, false);
});

test("rejects an empty target list", () => {
  const result = validateScope(
    validScope({ allowedTargets: [] })
  );
  assert.equal(result.valid, false);
});

test("rejects an expired authorisation", () => {
  const result = validateScope(
    validScope({ expiresAt: "2020-01-01T00:00:00Z" })
  );
  assert.equal(result.valid, false);
});

test("rejects an unsupported test type", () => {
  const result = validateScope(
    validScope({ allowedTests: ["unauthorised-test"] })
  );
  assert.equal(result.valid, false);
});

test("rejects wildcard targets", () => {
  const result = validateScope(
    validScope({ allowedTargets: ["*.example.com"] })
  );
  assert.equal(result.valid, false);
});

test("rejects malformed target entries", () => {
  const result = validateScope(
    validScope({ allowedTargets: ["https://example.com/path"] })
  );
  assert.equal(result.valid, false);
});

test("allows an approved HTTPS security-header check", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "https://example.com/",
      testType: "security-headers"
    }
  );

  assert.equal(result.allowed, true);
  assert.equal(result.target, "example.com");
});

test("rejects a target outside approved scope", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "https://other.com/",
      testType: "security-headers"
    }
  );

  assert.equal(result.allowed, false);
});

test("rejects an unapproved test type", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "https://example.com/",
      testType: "malware-execution"
    }
  );

  assert.equal(result.allowed, false);
});

test("rejects HTTP connections", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "http://example.com/",
      testType: "security-headers"
    }
  );

  assert.equal(result.allowed, false);
});

test("rejects URL credentials", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "https://user:password@example.com/",
      testType: "security-headers"
    }
  );

  assert.equal(result.allowed, false);
});

test("rejects excluded paths", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "https://example.com/admin/settings",
      testType: "security-headers"
    }
  );

  assert.equal(result.allowed, false);
});

test("rejects malformed URLs", () => {
  const result = checkRequestScope(
    validScope(),
    {
      url: "not-a-valid-url",
      testType: "security-headers"
    }
  );

  assert.equal(result.allowed, false);
});

test("rejects missing request data", () => {
  const result = checkRequestScope(validScope(), null);
  assert.equal(result.allowed, false);
});
