import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { collectRaspInputs } from './inputs.js';
import { findCommandInjection } from './shell.js';
import { wrapMethod, type WrapSpec } from './wrap.js';

type CommandOf = (args: unknown[]) => string | undefined;

/** `exec` sempre usa shell: o comando é o primeiro argumento. */
const execCommand: CommandOf = (args) => (typeof args[0] === 'string' ? args[0] : undefined);

/** `spawn`/`execFile` só passam pelo shell com `{ shell: true }`; aí o comando é a junção dos argumentos. */
const spawnCommand: CommandOf = (args) => {
  if (typeof args[0] !== 'string') return undefined;
  const list = Array.isArray(args[1]) ? (args[1] as unknown[]) : [];
  const options = args.find(
    (arg, i) => i > 0 && arg !== null && typeof arg === 'object' && !Array.isArray(arg),
  ) as { shell?: unknown } | undefined;
  if (!options?.shell) return undefined;
  return [args[0], ...list.map(String)].join(' ');
};

const METHODS: Record<string, CommandOf> = {
  exec: execCommand,
  execSync: execCommand,
  spawn: spawnCommand,
  spawnSync: spawnCommand,
  execFile: spawnCommand,
  execFileSync: spawnCommand,
};

function specFor(commandOf: CommandOf): WrapSpec {
  return {
    driver: 'child_process',
    detect(args, context) {
      const command = commandOf(args);
      if (!command) return undefined;
      const input = findCommandInjection(command, collectRaspInputs(context.sources()));
      return input && { type: 'cmdi', severity: 5, location: input.location, rule: 'rasp.cmdi.child_process', layer: 'rasp' };
    },
    // Estas funções devolvem o processo filho; uma exceção na chamada é o único canal que não
    // quebra quem usa o valor de retorno (é também como elas reportam argumentos inválidos).
    delivery: () => ({ via: 'throw' }),
  };
}

/**
 * Camada RASP para `node:child_process`: confere comandos que passam por um shell
 * (`exec`, `execSync` e `spawn`/`execFile` com `shell: true`). Chamadas sem shell, com a
 * lista de argumentos separada, não permitem injeção de comando e não são verificadas.
 *
 * No modo `block`, a chamada lança `VigiloBlockedError` e o processo não é criado.
 *
 * ```js
 * import { instrumentChildProcess } from '@vigilo/express';
 * instrumentChildProcess();
 * ```
 */
export function instrumentChildProcess(): boolean {
  let patched = false;
  for (const [name, commandOf] of Object.entries(METHODS)) {
    patched = wrapMethod(childProcess, name, specFor(commandOf)) || patched;
  }
  syncBuiltinESMExports();
  return patched;
}
