// Muda a versão de todos os pacotes publicados e do SDK_VERSION de uma vez.
//
//   node scripts/set-version.mjs 0.1.0
import { readFileSync, writeFileSync } from 'node:fs';
import { PACKAGES } from './packages.mjs';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version ?? '')) {
  console.error('uso: node scripts/set-version.mjs <versão semver, ex.: 0.1.0>');
  process.exit(1);
}

for (const name of PACKAGES) {
  const path = `packages/${name}/package.json`;
  const manifest = JSON.parse(readFileSync(path, 'utf8'));
  manifest.version = version;
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

const contractPath = 'packages/core/src/contract.ts';
const contract = readFileSync(contractPath, 'utf8');
writeFileSync(contractPath, contract.replace(/export const SDK_VERSION = '[^']+'/, `export const SDK_VERSION = '${version}'`));

console.log(`versão ${version} aplicada; rode pnpm build para regenerar packages/core/schemas/`);
