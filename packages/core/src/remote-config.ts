import type { Logger, Mode } from './types.js';

export interface RemoteConfigOptions {
  /** URL base da plataforma (a mesma da ingestão). */
  endpoint: string;
  apiKey: string;
  /** Intervalo entre consultas. Padrão: 60 s. */
  intervalMs?: number;
  /** Timeout de cada consulta. Padrão: 3 s. */
  timeoutMs?: number;
  logger?: Logger | undefined;
  onMode: (mode: Mode) => void;
}

const MODES: ReadonlySet<string> = new Set<Mode>(['monitor', 'block']);

/**
 * Consulta o modo do projeto definido no painel (`GET /v1/config`) ao iniciar e
 * periodicamente. Fail-open: nunca lança exceção; se a plataforma não responder,
 * o último modo conhecido continua valendo (no início, `monitor`).
 */
export class RemoteConfig {
  private timer: NodeJS.Timeout | undefined;
  private lastProblem: string | undefined;

  constructor(private readonly options: RemoteConfigOptions) {}

  start(): void {
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), this.options.intervalMs ?? 60_000);
    // Não impede o processo do cliente de encerrar.
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  async refresh(): Promise<void> {
    try {
      const response = await fetch(new URL('/v1/config', this.options.endpoint), {
        headers: { authorization: `Bearer ${this.options.apiKey}` },
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 3_000),
      });
      if (!response.ok) {
        this.problem(`http ${response.status}`, response.status === 401 ? 'confira a apiKey' : undefined);
        return;
      }
      const body = (await response.json()) as { mode?: unknown };
      if (typeof body.mode !== 'string' || !MODES.has(body.mode)) {
        this.problem('resposta inválida');
        return;
      }
      this.lastProblem = undefined;
      this.options.onMode(body.mode as Mode);
    } catch (error) {
      this.problem(error instanceof Error ? error.name : 'erro');
    }
  }

  /** Avisa uma vez por tipo de problema, não a cada consulta. */
  private problem(kind: string, hint?: string): void {
    if (this.lastProblem === kind) return;
    this.lastProblem = kind;
    this.options.logger?.warn('vigilo: não foi possível ler o modo do painel; mantendo o atual', { problem: kind, hint });
  }
}
