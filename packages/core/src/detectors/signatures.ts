import type { Severity, Threat, ThreatType } from '../types.js';

export interface Signature {
  id: string;
  type: ThreatType;
  severity: Severity;
  pattern: RegExp;
}

/**
 * Assinaturas da camada 1 (dentro da requisição). São propositalmente conservadoras:
 * no beta a lib roda em `monitor`, e cada falso positivo reportado vira um ajuste aqui.
 * A confirmação forte (a entrada alterou a estrutura da query) virá da camada RASP,
 * que envolve os drivers de banco.
 */
export const VALUE_SIGNATURES: Signature[] = [
  // SQL injection
  { id: 'sqli.union-select', type: 'sqli', severity: 4, pattern: /\bunion\b(?:\s+all)?\s+select\b/i },
  { id: 'sqli.tautology', type: 'sqli', severity: 4, pattern: /['"`]\s*(?:or|and)\s+['"`]?\w+['"`]?\s*(?:=|like)\s*['"`]?\w+/i },
  { id: 'sqli.numeric-tautology', type: 'sqli', severity: 3, pattern: /\b(?:or|and)\s+(\d+)\s*=\s*\1\b/i },
  { id: 'sqli.comment-terminator', type: 'sqli', severity: 3, pattern: /['"`]\s*(?:--|#|\/\*)/ },
  { id: 'sqli.stacked-query', type: 'sqli', severity: 5, pattern: /;\s*(?:drop|delete|truncate|insert|update|alter|create)\s+(?:table|from|into|database|\w+\s+set)\b/i },
  { id: 'sqli.time-based', type: 'sqli', severity: 4, pattern: /\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\s*[('"]/i },
  { id: 'sqli.info-schema', type: 'sqli', severity: 4, pattern: /\binformation_schema\b|\bpg_catalog\b|\bsysobjects\b/i },

  // NoSQL injection em strings (ex.: query string crua `user[$ne]=`)
  { id: 'nosqli.operator-string', type: 'nosqli', severity: 4, pattern: /\[\s*\$(?:ne|gt|gte|lt|lte|regex|where|in|nin|exists|expr|or|and)\s*\]/i },
  { id: 'nosqli.where-js', type: 'nosqli', severity: 4, pattern: /\$where\s*:|\bthis\.\w+\s*==/i },

  // Path traversal
  { id: 'traversal.dot-dot', type: 'traversal', severity: 4, pattern: /(?:^|[\\/])\.\.(?:[\\/]|$)/ },
  { id: 'traversal.sensitive-file', type: 'traversal', severity: 4, pattern: /\/etc\/(?:passwd|shadow|hosts)\b|\b(?:win|boot)\.ini\b|\/proc\/self\//i },

  // XSS refletido
  { id: 'xss.script-tag', type: 'xss', severity: 3, pattern: /<\s*script\b/i },
  { id: 'xss.event-handler', type: 'xss', severity: 3, pattern: /<[^>]+\bon(?:error|load|click|mouseover|focus|animationstart)\s*=/i },
  { id: 'xss.js-uri', type: 'xss', severity: 3, pattern: /\bjavascript\s*:/i },
  { id: 'xss.dangerous-tag', type: 'xss', severity: 3, pattern: /<\s*(?:iframe|object|embed|svg)\b[^>]*>/i },
];

/** Operadores do MongoDB que não deveriam aparecer como chaves vindas do usuário. */
export const NOSQL_OPERATOR_KEY = /^\$(?:ne|eq|gt|gte|lt|lte|regex|where|in|nin|exists|expr|or|and|not|nor|elemMatch|function|accumulator)$/;

/** User agents de scanners e ferramentas de ataque conhecidas. */
export const SCANNER_USER_AGENT =
  /\b(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|feroxbuster|ffuf|nuclei|zgrab|havij|w3af|arachni|jaeles|commix)\b/i;

/** Paths que só scanners costumam pedir. */
export const SCANNER_PATH =
  /(?:^|\/)(?:\.env|\.git\/(?:config|HEAD)|wp-login\.php|wp-admin|phpmyadmin|\.aws\/credentials|server-status|actuator\/env|\.DS_Store)(?:$|[/?])/i;

export function matchValue(value: string, location: string): Threat[] {
  const found: Threat[] = [];
  for (const signature of VALUE_SIGNATURES) {
    if (signature.pattern.test(value)) {
      found.push({ type: signature.type, severity: signature.severity, location, rule: signature.id, layer: 'signature' });
    }
  }
  return found;
}
