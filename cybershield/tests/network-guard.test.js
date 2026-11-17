
import test from "node:test";
import assert from "node:assert/strict";

import {
  createNetworkGuard
} from "../governance/network-guard.js";

const scope = {
  allowedTargets: ["example.com"]
};

const guard = createNetworkGuard({
  isPublicIp: () => true
});

test("rejects missing IP classifier", () => {
  assert.throws(
    () => createNetworkGuard(),
    /IP classification is required/
  );
});

test("rejects malformed URLs", async () => {
  const result = await guard.validateDestination(
    scope,
    "not-a-valid-url"
  );

  assert.equal(result.allowed, false);
});

test("rejects HTTP connections", async () => {
  const result = await guard.validateDestination(
    scope,
    "http://example.com"
  );

  assert.equal(result.allowed, false);
});

test("rejects embedded credentials", async () => {
  const result = await guard.validateDestination(
    scope,
    "https://user:password@example.com"
  );

  assert.equal(result.allowed, false);
});

test("rejects custom ports", async () => {
  const result = await guard.validateDestination(
    scope,
    "https://example.com:8080"
  );

  assert.equal(result.allowed, false);
});

test("rejects IP address targets", async () => {
  const result = await guard.validateDestination(
    scope,
    "https://127.0.0.1"
  );

  assert.equal(result.allowed, false);
});

test("rejects malformed hostnames", async () => {
  const result = await guard.validateDestination(
    scope,
    "https://-invalid.example.com"
  );

  assert.equal(result.allowed, false);
});

test("rejects unauthorised domains", async () => {
  const result = await guard.validateDestination(
    scope,
    "https://unauthorised.example.net"
  );

  assert.equal(result.allowed, false);
});

test("rejects invalid redirect chain data", async () => {
  const result = await guard.validateRedirectChain(
    scope,
    "https://example.com",
    "not-an-array"
  );

  assert.equal(result.allowed, false);
});

test("rejects excessive redirects", async () => {
  const redirects = Array(6).fill(
    "https://example.com"
  );

  const result = await guard.validateRedirectChain(
    scope,
    "https://example.com",
    redirects
  );

  assert.equal(result.allowed, false);
  assert.equal(result.reason, "Redirect limit exceeded");
});

test("rejects insecure redirect destinations", async () => {
  const result = await guard.validateRedirectChain(
    scope,
    "https://example.com",
    ["http://example.com"]
  );

  assert.equal(result.allowed, false);
});
