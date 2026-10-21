import {
  createVigilo,
  headerValue,
  normalizeRoutePath,
  resolveClientIp,
  type Decision,
  type NormalizedRequest,
  type VigiloClient,
  type VigiloOptions,
} from '@vigilo/core';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

export type ShieldOptions = VigiloOptions & {
  /** Reaproveita um cliente já criado (ex.: compartilhado entre apps). */
  client?: VigiloClient;
  /** Resposta enviada quando a requisição é bloqueada. Padrão: 403 com JSON. */
  onBlock?: (req: Request, res: Response, decision: Decision) => void;
};

export type ShieldMiddleware = RequestHandler & { client: VigiloClient };

/**
 * Middleware do Vigilo para Express 4 e 5.
 *
 * Registre depois dos body parsers (`express.json()`), para que o corpo seja inspecionado,
 * e antes das rotas:
 *
 * ```js
 * app.use(express.json());
 * app.use(shield({ apiKey: process.env.VIGILO_KEY }));
 * ```
 */
export function shield(options: ShieldOptions = {}): ShieldMiddleware {
  const client = options.client ?? createVigilo(options);
  const onBlock =
    options.onBlock ?? ((_req: Request, res: Response) => void res.status(403).json({ error: 'Forbidden' }));

  const middleware = (req: Request, res: Response, next: NextFunction) => {
    let normalized: NormalizedRequest;
    let decision: Decision;
    const start = process.hrtime.bigint();

    try {
      normalized = toNormalized(req, client);
      decision = client.inspect(normalized);
    } catch {
      next();
      return;
    }

    res.once('finish', () => {
      try {
        // O padrão da rota só é conhecido depois do roteamento.
        if (req.route?.path && typeof req.route.path === 'string') {
          normalized.route = `${req.baseUrl ?? ''}${req.route.path}`;
        }
        const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
        client.record(normalized, { status: res.statusCode, durationMs, decision });
      } catch {
        // fail-open
      }
    });

    if (decision.block) {
      try {
        onBlock(req, res, decision);
        return;
      } catch {
        // Se a resposta de bloqueio falhar, a requisição segue.
      }
    }
    next();
  };

  return Object.assign(middleware, { client });
}

function toNormalized(req: Request, client: VigiloClient): NormalizedRequest {
  const path = req.path ?? req.url ?? '/';
  return {
    method: req.method,
    route: normalizeRoutePath(path),
    path,
    query: (req.query ?? {}) as Record<string, unknown>,
    headers: req.headers,
    body: req.body,
    ip: resolveClientIp(req.socket?.remoteAddress, req.headers['x-forwarded-for'], client.trustProxy),
    srcPort: req.socket?.remotePort,
    userAgent: headerValue(req.headers['user-agent']),
  };
}

export { createVigilo } from '@vigilo/core';
export type { VigiloClient, VigiloOptions } from '@vigilo/core';
