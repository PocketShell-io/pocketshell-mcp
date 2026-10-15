import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { build } from 'esbuild';
const clientCommit = '1384f1b8a0d30a5e227f0c1b2bf87594696f6b56';
const coreCommit = 'e87040d19773a710c6813307c98391209b3ddbe1';
// The consent page's key vault: @pocketshell/core keyVault (vault v1 reference implementation).
const vaultCoreCommit = '8f7b178c3116ffca1996abb99ed86d9561ccb690';
const temp = process.argv[2] ? null : mkdtempSync(join(tmpdir(), 'mcp-build-'));
const client = process.argv[2] ? resolve(process.argv[2]) : join(temp, 'pocketshell-client');
const vaultCore = process.argv[3] ? resolve(process.argv[3]) : join(temp || mkdtempSync(join(tmpdir(), 'mcp-vault-')), 'pocketshell-core-vault');
function run(command, args, cwd) { execFileSync(command, args, { cwd, stdio: 'inherit' }); }
try {
  if (temp) {
    for (const [repo, directory, commit] of [['pocketshell-core', 'pocketshell-core', coreCommit], ['pocketshell-tui-client', 'pocketshell-client', clientCommit]]) {
      const dir = join(temp, directory);
      run('git', ['clone', '--quiet', `https://github.com/PocketShell-io/${repo}.git`, dir]);
      run('git', ['checkout', '--quiet', commit], dir);
      run('npm', ['ci', '--ignore-scripts'], dir);
      if (repo === 'pocketshell-core') run('npm', ['run', 'build'], dir);
    }
  }
  if (process.argv[3]) {
    // A local checkout must be exactly the pinned, reviewed commit.
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: vaultCore, encoding: 'utf8' }).trim();
    if (head !== vaultCoreCommit) throw new Error(`Key vault core checkout is at ${head}, expected pinned ${vaultCoreCommit}`);
  } else {
    run('git', ['clone', '--quiet', 'https://github.com/PocketShell-io/pocketshell-core.git', vaultCore]);
    run('git', ['checkout', '--quiet', vaultCoreCommit], vaultCore);
    run('npm', ['ci', '--ignore-scripts'], vaultCore);
  }
  mkdirSync('vendor', { recursive: true });
  await build({ entryPoints: [join(client, 'src/cli.ts')], outfile: 'vendor/psc.mjs', bundle: true, platform: 'node', target: 'node24', format: 'esm', banner: { js: "import { createRequire as __pscCreateRequire } from 'node:module'; const require = __pscCreateRequire(import.meta.url);" } });
  await build({ entryPoints: [join(client, 'src/clientCore.ts')], outfile: 'vendor/client-core.mjs', bundle: true, platform: 'node', target: 'node24', format: 'esm', banner: { js: "import { createRequire as __pscCreateRequire } from 'node:module'; const require = __pscCreateRequire(import.meta.url);" } });
  // One ESM file for browsers and Node (WebCrypto + hash-wasm WASM), served to the consent page.
  await build({ entryPoints: [join(vaultCore, 'src/keyVault/index.ts')], outfile: 'vendor/key-vault.mjs', bundle: true, platform: 'neutral', mainFields: ['module', 'main'], target: ['es2022'], format: 'esm', legalComments: 'none' });
  // Core's known-answer vectors (throwaway values) let the tests check this exact bundle.
  copyFileSync(join(vaultCore, 'tests/keyVault/fixtures/vault-v1-vectors.json'), 'vendor/vault-v1-vectors.json');
  console.log('Built shared PocketShell core, CLI runtimes and key vault bundle (excluded from Git).');
} finally {
  if (temp) rmSync(temp, { recursive: true, force: true });
  else if (!process.argv[3]) rmSync(dirname(vaultCore), { recursive: true, force: true });
}
