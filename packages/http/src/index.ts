import type { IncomingMessage, RequestListener, ServerResponse } from 'node:http';
import {
  createVigilo,
  headerValue,
  normalizeRoutePath,
  resolveClientIp,
  runWithContext,
  type Decision,
  type NormalizedRequest,
  type RequestContext,
  type VigiloClient,
  type VigiloOptions,
} from '@vigilo/core';

export type WithVigiloOptions = VigiloOptions & {
  client?: VigiloClient;
  onBlock?: (req: IncomingMessage, res: ServerResponse, decision: Decision) => void;
};

export type ProtectedListener = RequestListener & { client: VigiloClient };

/**
 * Envolve um handler de `node:http`.
 *
 * O corpo não é inspecionado aqui: ler o stream o consumiria antes do seu handler.
 * Path, query string e cabeçalhos são inspecionados normalmente.
 *
 * ```js
 * http.createServer(withVigilo(handler, { apiKey: process.env.VIGILO_KEY }));
 * ```
 */
export function withVigilo(handler: RequestListener, options: WithVigiloOptions = {}): ProtectedListener {
  const client = options.client ?? createVigilo(options);
  const onBlock =
    options.onBlock ??
    ((_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Forbidden' }));
    });

  const listener: RequestListener = (req, res) => {
    let normalized: NormalizedRequest;
    let decision: Decision;
    let context: RequestContext;
    const start = process.hrtime.bigint();

    try {
      normalized = toNormalized(req, client);
      decision = client.inspect(normalized);
      const sources = { query: normalized.query, path: normalized.path, headers: req.headers };
      context = client.createContext(() => sources);
    } catch {
      handler(req, res);
      return;
    }

    res.once('finish', () => {
      try {
        const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
        client.record(normalized, { status: res.statusCode, durationMs, decision, context });
      } catch {
        // fail-open
      }
    });

    if (decision.block) {
      try {
        onBlock(req, res, decision);
        return;
      } catch {
        // fail-open
      }
    }
    runWithContext(context, () => handler(req, res));
  };

  return Object.assign(listener, { client });
}

function toNormalized(req: IncomingMessage, client: VigiloClient): NormalizedRequest {
  const rawUrl = req.url ?? '/';
  // O path cru (sem resolver `../`) é o que importa para detectar traversal.
  const path = rawUrl.split('?')[0] || '/';
  const url = new URL(rawUrl, 'http://localhost');
  const query: Record<string, string | string[]> = {};
  for (const key of new Set(url.searchParams.keys())) {
    const values = url.searchParams.getAll(key);
    query[key] = values.length === 1 ? values[0]! : values;
  }
  return {
    method: req.method ?? 'GET',
    route: normalizeRoutePath(path),
    path,
    query,
    headers: req.headers,
    ip: resolveClientIp(req.socket?.remoteAddress, req.headers['x-forwarded-for'], client.trustProxy),
    srcPort: req.socket?.remotePort,
    userAgent: headerValue(req.headers['user-agent']),
  };
}

export { createVigilo, instrumentPg, VigiloBlockedError } from '@vigilo/core';
export type { VigiloClient, VigiloOptions } from '@vigilo/core';
