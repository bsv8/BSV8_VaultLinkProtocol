import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
test('native device policy: plugin single limit and App cross-channel cumulative limit survive persistence', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vlp-native-policy-'));
  try {
    const binary = join(dir, 'policy');
    const build = spawnSync(process.env.CXX ?? 'c++', ['-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', fileURLToPath(new URL('./native-policy.cpp', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(build.status, 0, build.stderr);
    const run = spawnSync(binary, [join(dir, 'state')], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
