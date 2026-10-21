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
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

export type VigiloFastifyOptions = VigiloOptions & {
  client?: VigiloClient;
  onBlock?: (request: FastifyRequest, reply: FastifyReply, decision: Decision) => unknown;
};

declare module 'fastify' {
  interface FastifyInstance {
    vigilo: VigiloClient;
  }
}

interface State {
  normalized: NormalizedRequest;
  decision: Decision;
  context?: RequestContext;
}

const plugin: FastifyPluginAsync<VigiloFastifyOptions> = async (fastify, options) => {
  const client = options.client ?? createVigilo(options);
  const states = new WeakMap<FastifyRequest, State>();
  const onBlock =
    options.onBlock ?? ((_request: FastifyRequest, reply: FastifyReply) => reply.code(403).send({ error: 'Forbidden' }));

  fastify.decorate('vigilo', client);

  // preHandler: o corpo já foi parseado e o padrão da rota é conhecido.
  fastify.addHook('preHandler', async (request, reply) => {
    let state: State;
    try {
      const normalized = toNormalized(request, client);
      state = { normalized, decision: client.inspect(normalized) };
      states.set(request, state);
    } catch {
      return;
    }
    if (state.decision.block) {
      try {
        return await onBlock(request, reply, state.decision);
      } catch {
        // fail-open
      }
    }
  });

  // Hook em estilo callback, registrado por último: o handler roda como continuação de `done`,
  // então herda o contexto da RASP. Não roda se a requisição foi bloqueada acima.
  fastify.addHook('preHandler', (request, _reply, done) => {
    const state = states.get(request);
    let context: RequestContext;
    try {
      if (!state) return done();
      context = client.createContext(() => ({
        query: request.query,
        body: request.body,
        params: request.params,
        path: state.normalized.path,
        headers: request.headers,
      }));
      state.context = context;
    } catch {
      return done();
    }
    runWithContext(context, () => done());
  });

  fastify.addHook('onResponse', async (request, reply) => {
    try {
      // 404 e erros antes do preHandler não passam pelo hook acima.
      const state = states.get(request) ?? {
        normalized: toNormalized(request, client),
        decision: { threats: [], block: false },
      };
      if (!states.has(request)) state.decision = client.inspect(state.normalized);
      client.record(state.normalized, {
        status: reply.statusCode,
        durationMs: reply.elapsedTime,
        decision: state.decision,
        context: state.context,
      });
    } catch {
      // fail-open
    }
  });

  fastify.addHook('onClose', async () => {
    await client.close();
  });
};

function toNormalized(request: FastifyRequest, client: VigiloClient): NormalizedRequest {
  const path = request.url.split('?')[0] ?? '/';
  return {
    method: request.method,
    route: request.routeOptions?.url ?? normalizeRoutePath(path),
    path,
    query: (request.query ?? {}) as Record<string, unknown>,
    headers: request.headers,
    body: request.body,
    ip: resolveClientIp(request.socket?.remoteAddress, request.headers['x-forwarded-for'], client.trustProxy),
    srcPort: request.socket?.remotePort,
    userAgent: headerValue(request.headers['user-agent']),
  };
}

/**
 * Plugin do Vigilo para Fastify 5.
 *
 * ```js
 * await app.register(vigilo, { apiKey: process.env.VIGILO_KEY });
 * ```
 */
export const vigilo = fp(plugin, { fastify: '5.x', name: '@vigilo/fastify' });
export default vigilo;
export {
  createVigilo,
  instrumentChildProcess,
  instrumentFs,
  instrumentMongodb,
  instrumentMysql2,
  instrumentPg,
  VigiloBlockedError,
} from '@vigilo/core';
export type { VigiloClient, VigiloOptions } from '@vigilo/core';
