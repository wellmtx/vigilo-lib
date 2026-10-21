export type Mode = 'monitor' | 'block';

export type ThreatType =
  | 'sqli'
  | 'nosqli'
  | 'traversal'
  | 'xss'
  | 'scanner'
  | 'scan'
  | 'bruteforce'
  | 'ratelimit'
  /** Reservado para a camada RASP (`child_process`). */
  | 'cmdi';

/** Camada que produziu o sinal: assinatura na requisição, RASP no driver ou estado por IP. */
export type ThreatLayer = 'signature' | 'rasp' | 'ip';

/** 1 = informativo, 5 = crítico. */
export type Severity = 1 | 2 | 3 | 4 | 5;

export interface Threat {
  type: ThreatType;
  severity: Severity;
  /** Onde o sinal foi encontrado, ex.: "query.id", "body.user.name", "path", "header.user-agent". */
  location: string;
  /** Regra que disparou (útil para depurar falsos positivos). */
  rule: string;
  layer: ThreatLayer;
}

export type HeaderValue = string | string[] | undefined;

/** Requisição normalizada, independente do framework. */
export interface NormalizedRequest {
  method: string;
  /** Padrão da rota (`/users/:id`) quando o framework informa; senão, o path normalizado. */
  route: string;
  /** Path concreto, sem query string. */
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, HeaderValue>;
  body?: unknown;
  ip: string;
  srcPort?: number | undefined;
  userAgent?: string | undefined;
}

export interface Decision {
  threats: Threat[];
  /** true quando o modo é `block` e alguma ameaça atingiu a severidade de bloqueio. */
  block: boolean;
}

export interface ResponseOutcome {
  status: number;
  durationMs: number;
  decision: Decision;
}

/**
 * Evento enviado para a API de ingestão. Contrato congelado na versão 1 do schema
 * (ver `docs/event-contract.md` e `contract.ts`): mudanças só aditivas e opcionais.
 */
export interface VigiloEvent {
  eventId: string;
  ts: string;
  method: string;
  route: string;
  status: number;
  durationMs: number;
  ip: string;
  srcPort: number | null;
  userAgent: string | null;
  threatType: ThreatType | null;
  severity: Severity | null;
  threats: Threat[];
  blocked: boolean;
  /** Só em eventos suspeitos, já mascarado e truncado. */
  payload: string | null;
}

export interface Logger {
  debug(message: string, meta?: unknown): void;
  warn(message: string, meta?: unknown): void;
}
