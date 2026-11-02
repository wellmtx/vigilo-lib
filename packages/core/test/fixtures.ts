import { expect } from 'vitest';
import type { NormalizedRequest } from '../src/types.js';

export function request(overrides: Partial<NormalizedRequest> = {}): NormalizedRequest {
  return {
    method: 'GET',
    route: '/users/:id',
    path: '/users/42',
    query: {},
    headers: {},
    ip: '203.0.113.10',
    srcPort: 51234,
    userAgent: 'Mozilla/5.0',
    ...overrides,
  };
}

/** Callsite esperado quando o próprio teste chama o driver (o caminho depende do diretório do vitest). */
export function callsiteAt(testFile: string, line: number) {
  // Os chamadores dependem do vitest: o teste confere só o ponto da chamada.
  return expect.objectContaining({
    file: expect.stringMatching(new RegExp(`(^|/)test/${testFile.replace(/\./g, '\\.')}$`)),
    line,
    column: expect.any(Number),
    function: null,
  });
}
