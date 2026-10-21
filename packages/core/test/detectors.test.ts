import { describe, expect, it } from 'vitest';
import { detect } from '../src/detectors/index.js';
import { request } from './fixtures.js';

const types = (req: Parameters<typeof detect>[0]) => detect(req).map((t) => t.type);

describe('detect: ataques conhecidos', () => {
  it.each([
    ["1' OR '1'='1", 'sqli'],
    ['1 UNION SELECT username, password FROM users', 'sqli'],
    ["admin'--", 'sqli'],
    ['1; DROP TABLE users', 'sqli'],
    ["1' AND SLEEP(5)--", 'sqli'],
    ['../../etc/passwd', 'traversal'],
    ['%252e%252e%252fetc%252fpasswd', 'traversal'],
    ['<script>alert(1)</script>', 'xss'],
    ['<img src=x onerror=alert(1)>', 'xss'],
    ['javascript:alert(document.cookie)', 'xss'],
    ["' or true--", 'sqli'],
    ['1 OR true', 'sqli'],
    ["x' AND email IS NULL; --", 'sqli'],
    ["' OR ''='", 'sqli'],
    ["') OR ('1'='1", 'sqli'],
    ['-1 OR 2>1', 'sqli'],
    ['1/**/OR/**/1=1', 'sqli'],
    ["1' ORDER BY 3--", 'sqli'],
    ['<details open ontoggle=alert(1)>', 'xss'],
  ])('detecta %s em query', (payload, expected) => {
    expect(types(request({ query: { q: payload } }))).toContain(expected);
  });

  it('detecta operador NoSQL como chave do body', () => {
    const threats = detect(request({ method: 'POST', body: { user: 'admin', password: { $ne: null } } }));
    expect(threats).toContainEqual(expect.objectContaining({ type: 'nosqli', location: 'body.password.$ne' }));
  });

  it('detecta traversal no próprio path', () => {
    expect(types(request({ path: '/files/..%2f..%2fetc/passwd' }))).toContain('traversal');
  });

  it('detecta o ffuf pelo user agent padrão', () => {
    expect(types(request({ userAgent: 'Fuzz Faster U Fool v2.1.0' }))).toContain('scanner');
  });

  it('detecta user agent de scanner e paths sensíveis', () => {
    const found = types(request({ path: '/.env', userAgent: 'sqlmap/1.7.2#stable' }));
    expect(found).toContain('scanner');
    expect(found).toContain('scan');
  });

  it('inspeciona valores aninhados e informa a localização', () => {
    const threats = detect(request({ body: { filters: [{ name: "x' OR 'a'='a" }] } }));
    expect(threats[0]?.location).toBe('body.filters[0].name');
  });
});

describe('detect: tráfego legítimo (falsos positivos)', () => {
  it.each([
    ['Maria da Silva'],
    ["O'Brien"],
    ['Selecione a melhor opção para o seu plano'],
    ['união de dados e seleção de clientes'],
    ['2024-10-21T10:00:00Z'],
    ['https://exemplo.com.br/pagina?ref=123'],
    ['Preço: R$ 1.299,90 — desconto de 10%'],
    ['Leia o arquivo docs/README.md'],
    ['a <b>negrito</b> e <i>itálico</i>'],
    ['Isso é true ou false?'],
    ['nota 10 or 9, tanto faz'],
    ['entre 3 or 4 dias úteis'],
    ['ordenar por data; -- ver depois'],
    ['/* comentário */ no código'],
    ['order by 2 colunas'],
    ['a <online> tag'],
    ["it's null or empty"],
  ])('não sinaliza %s', (value) => {
    expect(detect(request({ query: { q: value }, body: { comment: value } }))).toEqual([]);
  });

  it('não sinaliza chaves comuns que começam com letras', () => {
    expect(detect(request({ body: { name: 'x', email: 'a@b.com', price: 10 } }))).toEqual([]);
  });
});
