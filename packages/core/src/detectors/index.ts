import { collectKeys, collectValues, decodeValue } from '../normalize.js';
import type { NormalizedRequest, Threat } from '../types.js';
import { matchValue, NOSQL_OPERATOR_KEY, SCANNER_PATH, SCANNER_USER_AGENT } from './signatures.js';

/** Cabeçalhos inspecionados além do user agent (os demais raramente carregam payload). */
const INSPECTED_HEADERS = ['referer', 'x-forwarded-host', 'x-original-url', 'x-rewrite-url'];

/** Camada 1: verificações determinísticas sobre uma única requisição. */
export function detect(req: NormalizedRequest): Threat[] {
  const threats: Threat[] = [];

  const path = decodeValue(req.path);
  threats.push(...matchValue(path, 'path'));
  if (SCANNER_PATH.test(path)) {
    threats.push({ type: 'scan', severity: 2, location: 'path', rule: 'scan.sensitive-path', layer: 'signature' });
  }

  for (const { location, value } of collectValues(req.query, 'query')) {
    threats.push(...matchValue(value, location));
  }
  for (const { location, value } of collectValues(req.body, 'body')) {
    threats.push(...matchValue(value, location));
  }

  for (const { location, value } of [...collectKeys(req.query, 'query'), ...collectKeys(req.body, 'body')]) {
    if (NOSQL_OPERATOR_KEY.test(value)) {
      threats.push({ type: 'nosqli', severity: 4, location, rule: 'nosqli.operator-key', layer: 'signature' });
    }
  }

  for (const name of INSPECTED_HEADERS) {
    const raw = req.headers[name];
    const value = Array.isArray(raw) ? raw.join(',') : raw;
    if (value) threats.push(...matchValue(decodeValue(value), `header.${name}`));
  }

  if (req.userAgent && SCANNER_USER_AGENT.test(req.userAgent)) {
    threats.push({ type: 'scanner', severity: 2, location: 'header.user-agent', rule: 'scanner.user-agent', layer: 'signature' });
  }

  return dedupe(threats);
}

function dedupe(threats: Threat[]): Threat[] {
  const seen = new Set<string>();
  return threats.filter((threat) => {
    const key = `${threat.rule}|${threat.location}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function highestSeverity(threats: Threat[]): Threat | undefined {
  return threats.reduce<Threat | undefined>(
    (top, threat) => (!top || threat.severity > top.severity ? threat : top),
    undefined,
  );
}
