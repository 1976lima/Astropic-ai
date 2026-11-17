
import test from "node:test";
import assert from "node:assert/strict";

import { isPublicIp } from "../governance/ip-classifier.js";

test("accepts public IPv4 addresses", () => {
  assert.equal(isPublicIp("8.8.8.8"), true);
  assert.equal(isPublicIp("1.1.1.1"), true);
});

test("rejects private IPv4 addresses", () => {
  assert.equal(isPublicIp("10.0.0.1"), false);
  assert.equal(isPublicIp("172.16.0.1"), false);
  assert.equal(isPublicIp("192.168.1.1"), false);
});

test("rejects loopback and link-local IPv4", () => {
  assert.equal(isPublicIp("127.0.0.1"), false);
  assert.equal(isPublicIp("169.254.1.1"), false);
});

test("accepts public IPv6 addresses", () => {
  assert.equal(
    isPublicIp("2001:4860:4860::8888"),
    true
  );
});

test("rejects private and loopback IPv6", () => {
  assert.equal(isPublicIp("::1"), false);
  assert.equal(isPublicIp("fc00::1"), false);
  assert.equal(isPublicIp("fe80::1"), false);
});

test("rejects invalid IP addresses", () => {
  assert.equal(isPublicIp("999.999.999.999"), false);
  assert.equal(isPublicIp("not-an-ip"), false);
  assert.equal(isPublicIp(""), false);
  assert.equal(isPublicIp(null), false);
});
