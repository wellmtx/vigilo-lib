import type { Threat, ThreatType } from './types.js';

export interface TrackerOptions {
  /** Respostas 404 por IP que caracterizam varredura. Padrão: 30 em 60 s. */
  scanThreshold?: number;
  scanWindowMs?: number;
  /** Respostas 401/403 em rotas de login por IP que caracterizam força bruta. Padrão: 10 em 5 min. */
  bruteforceThreshold?: number;
  bruteforceWindowMs?: number;
  /** Requisições por IP (qualquer status) que caracterizam excesso de volume. Padrão: 600 em 60 s. 0 desativa. */
  rateLimitThreshold?: number;
  rateLimitWindowMs?: number;
  /** Por quanto tempo um IP sinalizado continua marcado. Padrão: 10 min. */
  flagTtlMs?: number;
  /** Rotas consideradas de autenticação. */
  loginRoute?: RegExp;
  /** Limite de IPs acompanhados em memória. */
  maxTrackedIps?: number;
}

/** Contador de janela deslizante aproximada (dois baldes): O(1) por requisição. */
interface VolumeCounter {
  windowStart: number;
  current: number;
  previous: number;
}

interface Flag {
  threat: Threat;
  expiresAt: number;
}

/**
 * Camada 2: estado por IP em memória, com janela deslizante.
 * Cada instância da API vê só o próprio tráfego; a visão consolidada fica na plataforma.
 */
export class IpTracker {
  private readonly hits = new Map<string, number[]>();
  private readonly volume = new Map<string, VolumeCounter>();
  /** Marcações ativas por IP, uma por tipo, para que um limite não apague o outro. */
  private readonly flags = new Map<string, Map<ThreatType, Flag>>();
  private readonly options: Required<TrackerOptions>;

  constructor(options: TrackerOptions = {}) {
    this.options = {
      scanThreshold: options.scanThreshold ?? 30,
      scanWindowMs: options.scanWindowMs ?? 60_000,
      bruteforceThreshold: options.bruteforceThreshold ?? 10,
      bruteforceWindowMs: options.bruteforceWindowMs ?? 300_000,
      rateLimitThreshold: options.rateLimitThreshold ?? 600,
      rateLimitWindowMs: options.rateLimitWindowMs ?? 60_000,
      flagTtlMs: options.flagTtlMs ?? 600_000,
      loginRoute: options.loginRoute ?? /(?:^|\/)(?:login|signin|sign-in|auth|session|token|oauth)(?:\/|$)/i,
      maxTrackedIps: options.maxTrackedIps ?? 10_000,
    };
  }

  /** Ameaças ativas para o IP (varredura, força bruta ou volume). */
  flagsFor(ip: string, now: number = Date.now()): Threat[] {
    const byType = this.flags.get(ip);
    if (!byType) return [];
    const active: Threat[] = [];
    for (const [type, flag] of byType) {
      if (flag.expiresAt <= now) byType.delete(type);
      else active.push(flag.threat);
    }
    if (byType.size === 0) this.flags.delete(ip);
    return active;
  }

  /** Primeira ameaça ativa para o IP, se houver. */
  flagFor(ip: string, now: number = Date.now()): Threat | undefined {
    return this.flagsFor(ip, now)[0];
  }

  /**
   * Registra a resposta e devolve uma ameaça quando um limite é ultrapassado.
   * Todos os contadores são atualizados mesmo quando mais de um dispara; os demais
   * ficam marcados e aparecem em `flagsFor` nas próximas requisições.
   */
  observe(ip: string, route: string, status: number, now: number = Date.now()): Threat | undefined {
    const o = this.options;
    let found: Threat | undefined;
    if (o.rateLimitThreshold > 0 && this.countVolume(ip, now) >= o.rateLimitThreshold) {
      found = this.flag(ip, { type: 'ratelimit', severity: 3, location: 'ip', rule: 'ratelimit.ip-volume', layer: 'ip' }, now);
    }
    if (status === 404) {
      if (this.count(`scan:${ip}`, o.scanWindowMs, now) >= o.scanThreshold) {
        found = this.flag(ip, { type: 'scan', severity: 3, location: 'ip', rule: 'scan.many-404', layer: 'ip' }, now) ?? found;
      }
    } else if ((status === 401 || status === 403) && o.loginRoute.test(route)) {
      if (this.count(`brute:${ip}`, o.bruteforceWindowMs, now) >= o.bruteforceThreshold) {
        found = this.flag(ip, { type: 'bruteforce', severity: 3, location: 'ip', rule: 'bruteforce.login-failures', layer: 'ip' }, now) ?? found;
      }
    }
    return found;
  }

  get size(): number {
    return Math.max(this.hits.size, this.volume.size);
  }

  /**
   * Estima as requisições na janela deslizante combinando o balde atual com uma fração
   * do anterior. Evita guardar um timestamp por requisição em IPs de alto volume.
   */
  private countVolume(ip: string, now: number): number {
    const windowMs = this.options.rateLimitWindowMs;
    const windowStart = now - (now % windowMs);
    let counter = this.volume.get(ip);
    if (!counter) {
      counter = { windowStart, current: 0, previous: 0 };
    } else if (counter.windowStart !== windowStart) {
      counter.previous = windowStart - counter.windowStart === windowMs ? counter.current : 0;
      counter.current = 0;
      counter.windowStart = windowStart;
    }
    counter.current++;
    this.volume.delete(ip);
    this.volume.set(ip, counter);
    this.evict();
    const elapsed = (now - windowStart) / windowMs;
    return counter.current + counter.previous * (1 - elapsed);
  }

  private count(key: string, windowMs: number, now: number): number {
    const since = now - windowMs;
    const list = (this.hits.get(key) ?? []).filter((t) => t > since);
    list.push(now);
    this.hits.delete(key);
    this.hits.set(key, list);
    this.evict();
    return list.length;
  }

  /** Só sinaliza na primeira vez dentro do TTL, para não gerar um alerta por requisição. */
  private flag(ip: string, threat: Threat, now: number): Threat | undefined {
    let byType = this.flags.get(ip);
    const current = byType?.get(threat.type);
    if (current && current.expiresAt > now) return undefined;
    if (!byType) {
      byType = new Map();
      this.flags.set(ip, byType);
    }
    byType.set(threat.type, { threat, expiresAt: now + this.options.flagTtlMs });
    return threat;
  }

  /** Remove as chaves mais antigas quando o limite de memória é atingido. */
  private evict(): void {
    for (const map of [this.hits, this.volume] as Map<string, unknown>[]) {
      while (map.size > this.options.maxTrackedIps) {
        const oldest = map.keys().next().value;
        if (oldest === undefined) break;
        map.delete(oldest);
      }
    }
  }
}
