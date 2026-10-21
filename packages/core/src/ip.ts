import { headerValue } from './normalize.js';
import type { HeaderValue } from './types.js';

export type TrustProxy = boolean | string[];

/** Remove o prefixo IPv4-mapeado (`::ffff:203.0.113.5` → `203.0.113.5`) e a zona IPv6 (`fe80::1%eth0`). */
export function normalizeIp(ip: string | undefined): string {
  if (!ip) return '0.0.0.0';
  const zone = ip.indexOf('%');
  const bare = zone === -1 ? ip : ip.slice(0, zone);
  return bare.startsWith('::ffff:') ? bare.slice(7) : bare;
}

const LOOPBACK_OR_PRIVATE = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|fc|fd)/i;

/**
 * Resolve o IP real do cliente.
 *
 * `X-Forwarded-For` só é considerado quando o socket vem de um proxy confiável;
 * do contrário qualquer atacante poderia forjar o próprio IP.
 * - `false` (padrão): usa sempre o IP do socket.
 * - `true`: confia em proxies em rede privada ou loopback (load balancer na mesma VPC).
 * - lista de IPs: confia apenas nesses proxies.
 */
export function resolveClientIp(socketIp: string | undefined, forwardedFor: HeaderValue, trustProxy: TrustProxy): string {
  const direct = normalizeIp(socketIp);
  if (!trustProxy) return direct;

  const isTrusted = (ip: string) =>
    trustProxy === true ? LOOPBACK_OR_PRIVATE.test(ip) : trustProxy.includes(ip);

  if (!isTrusted(direct)) return direct;

  const chain = (headerValue(forwardedFor) ?? '')
    .split(',')
    .map((part) => normalizeIp(part.trim()))
    .filter((part) => part && part !== '0.0.0.0');

  // Percorre da direita para a esquerda: o primeiro IP não confiável é o cliente.
  for (let i = chain.length - 1; i >= 0; i--) {
    const candidate = chain[i]!;
    if (!isTrusted(candidate)) return candidate;
  }
  return chain[0] ?? direct;
}
