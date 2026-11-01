/**
 * Cross-platform unit-test launcher.
 *
 * `node --test 'tests/*.test.ts'` relies on a glob: Windows cmd passes the
 * single quotes through literally and Node then runs zero tests and exits 0.
 * This lists the files itself, runs them with the same Node binary, and fails
 * loudly if it finds none or the Node version cannot strip types.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 6)) {
  console.error(`Unit tests need Node 22.6 or newer for type stripping; this is ${process.versions.node}.`);
  process.exit(1);
}

const files = readdirSync(here)
  .filter((name) => name.endsWith('.test.ts'))
  .sort()
  .map((name) => join(here, name));

if (files.length === 0) {
  console.error(`No *.test.ts files found in ${here}. Refusing to report success with zero tests.`);
  process.exit(1);
}

console.log(`Running ${files.length} test files`);
const result = spawnSync(process.execPath, ['--test', '--experimental-strip-types', ...files], { stdio: 'inherit' });
if (result.error) {
  console.error(result.error);
  process.exit(1);
}
process.exit(result.status ?? 1);
