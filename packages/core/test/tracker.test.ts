import { describe, expect, it } from 'vitest';
import { IpTracker } from '../src/tracker.js';

describe('IpTracker', () => {
  it('sinaliza varredura após muitos 404 na janela, uma única vez', () => {
    const tracker = new IpTracker({ scanThreshold: 3, scanWindowMs: 1_000 });
    const now = 1_000_000;
    expect(tracker.observe('1.1.1.1', '/a', 404, now)).toBeUndefined();
    expect(tracker.observe('1.1.1.1', '/b', 404, now + 1)).toBeUndefined();
    expect(tracker.observe('1.1.1.1', '/c', 404, now + 2)?.type).toBe('scan');
    expect(tracker.observe('1.1.1.1', '/d', 404, now + 3)).toBeUndefined();
    expect(tracker.flagFor('1.1.1.1', now + 4)?.type).toBe('scan');
  });

  it('descarta acessos fora da janela', () => {
    const tracker = new IpTracker({ scanThreshold: 2, scanWindowMs: 100 });
    tracker.observe('1.1.1.1', '/a', 404, 0);
    expect(tracker.observe('1.1.1.1', '/b', 404, 500)).toBeUndefined();
  });

  it('sinaliza força bruta só em rotas de login', () => {
    const tracker = new IpTracker({ bruteforceThreshold: 2 });
    expect(tracker.observe('2.2.2.2', '/orders', 401, 1)).toBeUndefined();
    expect(tracker.observe('2.2.2.2', '/orders', 401, 2)).toBeUndefined();
    tracker.observe('2.2.2.2', '/auth/login', 401, 3);
    expect(tracker.observe('2.2.2.2', '/auth/login', 401, 4)?.type).toBe('bruteforce');
  });

  it('expira a marcação após o TTL', () => {
    const tracker = new IpTracker({ scanThreshold: 1, flagTtlMs: 10 });
    tracker.observe('3.3.3.3', '/x', 404, 0);
    expect(tracker.flagFor('3.3.3.3', 5)).toBeDefined();
    expect(tracker.flagFor('3.3.3.3', 20)).toBeUndefined();
  });

  it('respeita o limite de IPs em memória', () => {
    const tracker = new IpTracker({ maxTrackedIps: 2 });
    tracker.observe('a', '/', 404, 0);
    tracker.observe('b', '/', 404, 0);
    tracker.observe('c', '/', 404, 0);
    expect(tracker.size).toBe(2);
  });

  describe('rate limit por volume', () => {
    const at = (second: number) => 6_000_000 + second * 1_000;

    it('sinaliza o IP que passa do limite na janela, uma única vez', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 5, rateLimitWindowMs: 10_000 });
      for (let i = 0; i < 4; i++) expect(tracker.observe('4.4.4.4', '/orders', 200, at(i))).toBeUndefined();
      expect(tracker.observe('4.4.4.4', '/orders', 200, at(4))).toMatchObject({
        type: 'ratelimit',
        rule: 'ratelimit.ip-volume',
        layer: 'ip',
      });
      expect(tracker.observe('4.4.4.4', '/orders', 200, at(5))).toBeUndefined();
      expect(tracker.flagFor('4.4.4.4', at(6))?.type).toBe('ratelimit');
    });

    it('conta requisições com qualquer status', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 3, rateLimitWindowMs: 10_000 });
      tracker.observe('4.4.4.4', '/a', 200, at(0));
      tracker.observe('4.4.4.4', '/b', 500, at(1));
      expect(tracker.observe('4.4.4.4', '/c', 302, at(2))?.type).toBe('ratelimit');
    });

    it('herda parte da janela anterior (janela deslizante, não fixa)', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 10, rateLimitWindowMs: 10_000 });
      // 8 requisições no fim de uma janela e 3 no começo da seguinte: rajada de 11 em ~2 s.
      for (let i = 0; i < 8; i++) tracker.observe('4.4.4.4', '/a', 200, 6_009_000 + i * 100);
      tracker.observe('4.4.4.4', '/a', 200, 6_010_100);
      tracker.observe('4.4.4.4', '/a', 200, 6_010_200);
      expect(tracker.observe('4.4.4.4', '/a', 200, 6_010_300)?.type).toBe('ratelimit');
    });

    it('não sinaliza tráfego legítimo abaixo do limite padrão (5 req/s por 1 min)', () => {
      const tracker = new IpTracker();
      for (let i = 0; i < 300; i++) {
        expect(tracker.observe('5.5.5.5', '/products/:id', 200, 6_000_000 + i * 200)).toBeUndefined();
      }
      expect(tracker.flagsFor('5.5.5.5', 6_060_000)).toEqual([]);
    });

    it('não soma o volume de IPs diferentes', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 3, rateLimitWindowMs: 10_000 });
      for (let i = 0; i < 10; i++) {
        expect(tracker.observe(`10.0.0.${i}`, '/a', 200, at(0))).toBeUndefined();
        expect(tracker.observe(`10.0.0.${i}`, '/a', 200, at(1))).toBeUndefined();
      }
    });

    it('esquece o volume depois de uma janela inteira sem tráfego', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 3, rateLimitWindowMs: 10_000 });
      tracker.observe('4.4.4.4', '/a', 200, at(0));
      tracker.observe('4.4.4.4', '/a', 200, at(1));
      expect(tracker.observe('4.4.4.4', '/a', 200, at(25))).toBeUndefined();
      expect(tracker.observe('4.4.4.4', '/a', 200, at(26))).toBeUndefined();
    });

    it('pode ser desativado com limite 0', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 0 });
      for (let i = 0; i < 2_000; i++) expect(tracker.observe('4.4.4.4', '/a', 200, at(0))).toBeUndefined();
    });

    it('mantém varredura e volume marcados ao mesmo tempo, sem alternar', () => {
      const tracker = new IpTracker({ rateLimitThreshold: 3, scanThreshold: 5, rateLimitWindowMs: 10_000 });
      const found = [];
      for (let i = 0; i < 10; i++) found.push(tracker.observe('6.6.6.6', '/x', 404, at(0) + i));
      expect(found.filter(Boolean).map((t) => t!.type).sort()).toEqual(['ratelimit', 'scan']);
      expect(tracker.flagsFor('6.6.6.6', at(1)).map((t) => t.type).sort()).toEqual(['ratelimit', 'scan']);
    });
  });
});
