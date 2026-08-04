import assert from 'node:assert/strict';
import test from 'node:test';

import {
  missingProofs,
  parseCargoTestList,
  parseCargoTestExecutable,
  proofPassedExactlyOnce,
  proofGroups,
  validateManifest,
} from './fleet-release-proof.mjs';

test('manifest contains exactly eight non-empty groups and unique tests', () => {
  const tests = validateManifest();
  assert.deepEqual(proofGroups.map((group) => group.id), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(tests.size, proofGroups.flatMap((group) => group.tests).length);
});

test('cargo listing parser accepts exact test records across line endings', () => {
  const names = parseCargoTestList('alpha::works: test\r\nbeta::works: test\n0 tests, 0 benchmarks\n');
  assert.deepEqual([...names], ['alpha::works', 'beta::works']);
});

test('cargo artifact parser selects the Coven binary test executable', () => {
  const artifact = JSON.stringify({
    reason: 'compiler-artifact',
    profile: { test: true },
    target: { name: 'coven', kind: ['bin'] },
    executable: '/tmp/coven-test',
  });
  assert.equal(parseCargoTestExecutable(`not-json\n${artifact}\n`), '/tmp/coven-test');
  assert.throws(() => parseCargoTestExecutable('{"reason":"build-finished"}\n'), /test executable/u);
});

test('missing or renamed required proof is release-blocking', () => {
  const all = proofGroups.flatMap((group) => group.tests);
  const renamed = new Set(all);
  const removed = all[0];
  renamed.delete(removed);
  renamed.add(`${removed}_renamed`);
  assert.deepEqual(missingProofs(renamed), [removed]);
  assert.deepEqual(missingProofs(new Set(all)), []);
});

test('malformed group coverage is rejected', () => {
  assert.throws(
    () => validateManifest([{ id: 1, name: 'only one', tests: ['one'] }]),
    /exactly 1\.\.8/u,
  );
});

test('an ignored or filtered exact proof is release-blocking', () => {
  assert.equal(
    proofPassedExactlyOnce('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
    true,
  );
  assert.equal(
    proofPassedExactlyOnce('test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;'),
    false,
  );
  assert.equal(
    proofPassedExactlyOnce('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'),
    false,
  );
});
