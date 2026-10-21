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
