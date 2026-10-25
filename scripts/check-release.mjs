// Confere se os pacotes estão prontos para publicar: todos com a mesma versão,
// igual ao SDK_VERSION enviado nos eventos e, se informada, à tag do release.
//
//   node scripts/check-release.mjs [v0.1.0]
import { readFileSync } from 'node:fs';
import { PACKAGES } from './packages.mjs';

const errors = [];
const manifests = PACKAGES.map((name) => JSON.parse(readFileSync(`packages/${name}/package.json`, 'utf8')));
const version = manifests[0].version;

for (const manifest of manifests) {
  if (manifest.version !== version) errors.push(`${manifest.name} está em ${manifest.version}, esperado ${version}`);
  if (manifest.publishConfig?.access !== 'public') errors.push(`${manifest.name} sem publishConfig.access "public"`);
  if (!manifest.repository?.url?.includes('github.com/')) errors.push(`${manifest.name} sem repository`);
}

const contract = readFileSync('packages/core/src/contract.ts', 'utf8');
const sdkVersion = contract.match(/export const SDK_VERSION = '([^']+)'/)?.[1];
if (sdkVersion !== version) errors.push(`SDK_VERSION em contract.ts é ${sdkVersion}, esperado ${version}`);

const tag = process.argv[2];
if (tag && tag !== `v${version}`) errors.push(`tag ${tag} não corresponde à versão v${version}`);

if (errors.length > 0) {
  console.error(errors.map((e) => `- ${e}`).join('\n'));
  process.exit(1);
}
console.log(`ok: ${PACKAGES.length} pacotes em ${version}${tag ? ` (tag ${tag})` : ''}`);
