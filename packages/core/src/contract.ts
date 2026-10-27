import { DEFAULT_PAYLOAD_LIMIT } from './masking.js';
import type { Threat, ThreatLayer, ThreatType, VigiloEvent } from './types.js';

/**
 * Contrato entre a lib e a API de ingestão (`POST /v1/events`). Versão 1, congelada:
 * dentro dela só entram campos novos opcionais (a ingestão descarta campos que não conhece).
 * Mudança de tipo, remoção ou campo novo obrigatório exige `EVENT_SCHEMA_VERSION = 2`.
 * Detalhes em `docs/event-contract.md`.
 */
export const EVENT_SCHEMA_VERSION = 1;

export const SDK_NAME = '@vigilo/core';
/** Mantenha igual ao `version` do package.json. */
export const SDK_VERSION = '0.1.0';

/** Limites do contrato. A lib corta os valores antes de enviar; a ingestão rejeita o que passar disso. */
export const LIMITS = {
  batchSize: 500,
  method: 16,
  route: 512,
  userAgent: 512,
  threats: 32,
  location: 256,
  rule: 64,
  /** Bytes do payload mais o sufixo `…[truncated]`. */
  payload: DEFAULT_PAYLOAD_LIMIT + 16,
} as const;

export const THREAT_TYPES: readonly ThreatType[] = [
  'sqli',
  'nosqli',
  'traversal',
  'xss',
  'scanner',
  'scan',
  'bruteforce',
  'ratelimit',
  'cmdi',
];

export const THREAT_LAYERS: readonly ThreatLayer[] = ['signature', 'rasp', 'ip'];

/** Corpo do `POST /v1/events`, antes do gzip. */
export interface EventBatch {
  schemaVersion: typeof EVENT_SCHEMA_VERSION;
  sdk: { name: string; version: string };
  /** Horário do envio, para a plataforma estimar o desvio de relógio da instância. */
  sentAt: string;
  events: VigiloEvent[];
}

export function buildBatch(events: VigiloEvent[], now: Date = new Date()): EventBatch {
  return {
    schemaVersion: EVENT_SCHEMA_VERSION,
    sdk: { name: SDK_NAME, version: SDK_VERSION },
    sentAt: now.toISOString(),
    events,
  };
}

/** Corta uma string no limite do contrato. */
export function clip(value: string, max: number): string {
  return value.length > max ? value.slice(0, max) : value;
}

/** Ajusta as ameaças aos limites: as mais graves primeiro, até `LIMITS.threats`. */
export function clipThreats(threats: Threat[]): Threat[] {
  const sorted = threats.length > LIMITS.threats ? [...threats].sort((a, b) => b.severity - a.severity) : threats;
  return sorted.slice(0, LIMITS.threats).map((threat) => ({
    ...threat,
    location: clip(threat.location, LIMITS.location),
    rule: clip(threat.rule, LIMITS.rule),
  }));
}

const nullable = (schema: Record<string, unknown>) => ({ anyOf: [schema, { type: 'null' }] });

const THREAT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['type', 'severity', 'location', 'rule', 'layer'],
  properties: {
    type: { enum: THREAT_TYPES },
    severity: { type: 'integer', minimum: 1, maximum: 5 },
    location: { type: 'string', minLength: 1, maxLength: LIMITS.location },
    rule: { type: 'string', minLength: 1, maxLength: LIMITS.rule },
    layer: { enum: THREAT_LAYERS },
  },
} as const;

export const EVENT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'eventId',
    'ts',
    'method',
    'route',
    'status',
    'durationMs',
    'ip',
    'srcPort',
    'userAgent',
    'threatType',
    'severity',
    'threats',
    'blocked',
    'payload',
  ],
  properties: {
    eventId: {
      type: 'string',
      pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    },
    ts: { type: 'string', format: 'date-time' },
    method: { type: 'string', minLength: 1, maxLength: LIMITS.method },
    route: { type: 'string', minLength: 1, maxLength: LIMITS.route },
    status: { type: 'integer', minimum: 100, maximum: 999 },
    durationMs: { type: 'number', minimum: 0 },
    ip: { anyOf: [{ type: 'string', format: 'ipv4' }, { type: 'string', format: 'ipv6' }] },
    srcPort: nullable({ type: 'integer', minimum: 0, maximum: 65_535 }),
    userAgent: nullable({ type: 'string', maxLength: LIMITS.userAgent }),
    threatType: nullable({ enum: THREAT_TYPES }),
    severity: nullable({ type: 'integer', minimum: 1, maximum: 5 }),
    threats: { type: 'array', maxItems: LIMITS.threats, items: THREAT_SCHEMA },
    blocked: { type: 'boolean' },
    payload: nullable({ type: 'string', maxLength: LIMITS.payload }),
  },
} as const;

/**
 * JSON Schema (draft 2020-12) do corpo de `POST /v1/events`. Descreve exatamente o que a lib
 * emite; o build exporta para `schemas/event-batch.v1.json`. A ingestão não deve rejeitar
 * campos desconhecidos (ver "Regras de evolução" em `docs/event-contract.md`).
 */
export const EVENT_BATCH_SCHEMA = {
  $id: 'https://vigilosec.com/schemas/event-batch/v1.json',
  type: 'object',
  additionalProperties: false,
  required: ['schemaVersion', 'sdk', 'sentAt', 'events'],
  properties: {
    schemaVersion: { const: EVENT_SCHEMA_VERSION },
    sdk: {
      type: 'object',
      additionalProperties: false,
      required: ['name', 'version'],
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 64 },
        version: { type: 'string', minLength: 1, maxLength: 32 },
      },
    },
    sentAt: { type: 'string', format: 'date-time' },
    events: { type: 'array', minItems: 1, maxItems: LIMITS.batchSize, items: EVENT_SCHEMA },
  },
} as const;
