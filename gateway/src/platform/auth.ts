import { createHmac, timingSafeEqual } from "node:crypto";
import { getAddress, verifyMessage, type Hex, type PublicClient } from "viem";
import { createSiweMessage, generateSiweNonce, parseSiweMessage, validateSiweMessage } from "viem/siwe";

/**
 * Sign-In with Ethereum (EIP-4361). The server writes the message (domain, nonce, expiry), the wallet signs it,
 * and the server checks the signature, its own nonce (single use, 10 minutes) and that the domain is this host.
 * A signed session cookie then carries the address.
 */
export class SiweAuth {
  private nonces = new Map<string, number>();
  constructor(
    private secret: string,
    /** For smart-contract wallets (EIP-1271 / 6492); EOAs verify offline. */
    private client?: PublicClient,
    private sessionDays = 7,
  ) {}

  message(p: { address: string; chainId: number; domain: string; uri: string }): string {
    for (const [n, t] of this.nonces) if (Date.now() - t > 10 * 60_000) this.nonces.delete(n);
    const nonce = generateSiweNonce();
    this.nonces.set(nonce, Date.now());
    return createSiweMessage({
      address: getAddress(p.address),
      chainId: p.chainId,
      domain: p.domain,
      uri: p.uri,
      nonce,
      version: "1",
      statement: "Sign in to Airlock. This signature proves you control this address; it costs nothing and sends no transaction.",
      issuedAt: new Date(),
      expirationTime: new Date(Date.now() + 10 * 60_000),
    });
  }

  /** Returns the lowercased address, or throws with a reason a person can act on. */
  async verify(message: string, signature: Hex, domain: string): Promise<string> {
    const m = parseSiweMessage(message);
    if (!m.nonce || !this.nonces.has(m.nonce)) throw new Error("sign-in expired or already used; try again");
    this.nonces.delete(m.nonce); // single use, whatever happens next
    if (!m.address || !validateSiweMessage({ message: m, domain })) throw new Error(`message is not for ${domain} or has expired`);
    const ok = this.client
      ? await this.client.verifyMessage({ address: m.address, message, signature }).catch(() => false)
      : await verifyMessage({ address: m.address, message, signature }).catch(() => false);
    if (!ok) throw new Error("signature does not match the address");
    return m.address.toLowerCase();
  }

  private mac(body: string) {
    return createHmac("sha256", `airlock/session/v1|${this.secret}`).update(body).digest("base64url");
  }

  session(address: string): { value: string; maxAge: number } {
    const maxAge = this.sessionDays * 86400;
    const body = Buffer.from(JSON.stringify({ a: address.toLowerCase(), exp: Date.now() + maxAge * 1000 })).toString("base64url");
    return { value: `${body}.${this.mac(body)}`, maxAge };
  }

  /** The signed-in address, if the cookie is ours and unexpired. */
  read(cookie?: string): string | undefined {
    if (!cookie) return;
    const [body, sig] = cookie.split(".");
    if (!body || !sig) return;
    const want = Buffer.from(this.mac(body));
    const got = Buffer.from(sig);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return;
    try {
      const { a, exp } = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
      return typeof a === "string" && exp > Date.now() ? a : undefined;
    } catch {
      return;
    }
  }
}
