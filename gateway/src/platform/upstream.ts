import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

/**
 * People type model URLs into a hosted gateway, and the server then fetches them. Without a check, a URL could
 * point the server at its own network (cloud metadata, the platform's local model, other services on the box).
 * Hosted: only public addresses. Self-hosted (ALLOW_PRIVATE_UPSTREAMS=1): anything, since it's your own network.
 */
const blocked = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, cloud metadata
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const)
  blocked.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [
  ["::", 128],
  ["::1", 128],
  // No v4-mapped (::ffff:0:0/96) or NAT64 rules here: BlockList matches plain IPv4 addresses against them too,
  // which would block every public v4 host. Mapped addresses are unwrapped and checked as v4 in isPrivate.
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["ff00::", 8],
] as const)
  blocked.addSubnet(net, bits, "ipv6");

export function isPrivate(ip: string): boolean {
  const mapped = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return blocked.check(mapped[1], "ipv4");
  return blocked.check(ip, isIP(ip) === 6 ? "ipv6" : "ipv4");
}

/** Returns why the URL can't be used, or undefined when it's fine. The URL is normalized (no trailing slash). */
export async function checkUpstream(raw: string, allowPrivate: boolean): Promise<{ url?: string; error?: string }> {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { error: "not a URL" };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { error: "must be http(s)" };
  if (u.username || u.password) return { error: "put credentials in the API key field, not the URL" };
  if (u.search || u.hash) return { error: "base URL only (no query or fragment)" };
  const url = u.toString().replace(/\/+$/, "");
  if (allowPrivate) return { url };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  let addrs: string[];
  try {
    addrs = isIP(host) ? [host] : (await lookup(host, { all: true })).map((a) => a.address);
  } catch {
    return { error: `can't resolve ${host}` };
  }
  if (!addrs.length) return { error: `can't resolve ${host}` };
  const bad = addrs.find(isPrivate);
  if (bad) return { error: `${host} resolves to a private address (${bad}). Expose it with a public URL, e.g. a Cloudflare tunnel` };
  return { url };
}
