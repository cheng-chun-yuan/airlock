import { test } from "node:test";
import assert from "node:assert/strict";
import { checkUpstream, isPrivate } from "./upstream";

test("private, loopback, link-local and mapped addresses are refused", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"])
    assert.equal(isPrivate(ip), true, ip);
});

test("public addresses pass", () => {
  for (const ip of ["162.159.140.245", "8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"]) assert.equal(isPrivate(ip), false, ip);
});

test("URL shape: scheme, credentials, query; private hosts only when allowed", async () => {
  assert.match((await checkUpstream("ftp://x.example", false)).error!, /http/);
  assert.match((await checkUpstream("https://u:p@x.example", false)).error!, /credentials/);
  assert.match((await checkUpstream("https://x.example/v1?a=1", false)).error!, /query/);
  assert.match((await checkUpstream("http://127.0.0.1:8000/v1", false)).error!, /private/);
  assert.deepEqual(await checkUpstream("http://127.0.0.1:8000/v1/", true), { url: "http://127.0.0.1:8000/v1" });
});
