
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
test("rejects reserved and special IPv4 ranges", () => {
  assert.equal(isPublicIp("224.0.0.1"), false);
  assert.equal(isPublicIp("240.0.0.1"), false);
  assert.equal(isPublicIp("192.0.2.1"), false);
  assert.equal(isPublicIp("198.18.0.1"), false);
  assert.equal(isPublicIp("203.0.113.1"), false);
});

test("rejects IPv6 multicast and documentation addresses", () => {
  assert.equal(isPublicIp("ff02::1"), false);
  assert.equal(isPublicIp("2001:db8::1"), false);
});

test("handles IPv4-mapped IPv6 addresses", () => {
  assert.equal(isPublicIp("::ffff:192.168.1.1"), false);
  assert.equal(isPublicIp("::ffff:8.8.8.8"), true);
});

test("rejects IPv6 transition addresses", () => {
  assert.equal(isPublicIp("2002::1"), false);
});
