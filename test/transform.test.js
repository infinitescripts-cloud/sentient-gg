import test from 'node:test';
import assert from 'node:assert/strict';
import { transformLuau, validateBasic } from '../src/transform.js';

test('minimizer removes comments and excess whitespace without changing quoted text', () => {
  const source = `-- comment\nlocal msg = "hello -- there"  -- trailing\nprint(msg)`;
  assert.equal(transformLuau(source), 'local msg="hello -- there" print(msg)');
});

test('basic validator accepts balanced delimiters', () => {
  assert.equal(validateBasic('local x = { a = (1 + 2) }').ok, true);
});

test('basic validator rejects mismatched delimiters', () => {
  assert.equal(validateBasic('local x = (1 + 2]').ok, false);
});

test('basic validator ignores delimiters inside strings', () => {
  assert.equal(validateBasic('local x = "{[("').ok, true);
});

test('preserves long bracket string contents exactly', () => {
  const source = 'local s = [=[hello  -- still text\n  world]=]';
  const output = transformLuau(source);
  assert.match(output, /\[=\[hello  -- still text\n  world\]=\]/);
});

test('keeps operator spacing that could change tokenization', () => {
  assert.equal(transformLuau('local x = a + +b'), 'local x=a+ +b');
  assert.equal(transformLuau('local x = a - -b'), 'local x=a- -b');
});

test('validates long bracket strings and comments', () => {
  assert.equal(validateBasic('local s = [==[ { not syntax ) ]==]').ok, true);
  assert.equal(validateBasic('--[=[ long comment [ { ]=]\nprint(1)').ok, true);
  assert.equal(validateBasic('local s = [=[unfinished').ok, false);
});

test('Worker health endpoint returns runtime metadata and security headers', async () => {
  const { default: worker } = await import('../src/index.js');
  const request = new Request('https://sentinel.example/api/health');
  const response = await worker.fetch(request, { APP_NAME: 'Sentinel', APP_VERSION: '3.0.0' }, { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  const data = await response.json();
  assert.equal(data.ok, true);
  assert.equal(data.version, '3.0.0');
});

test('Worker rejects cross-origin state-changing requests', async () => {
  const { default: worker } = await import('../src/index.js');
  const request = new Request('https://sentinel.example/api/login', {
    method: 'POST', headers: { Origin: 'https://attacker.example', 'Content-Type': 'application/json' }, body: '{}'
  });
  const response = await worker.fetch(request, {}, { waitUntil() {} });
  assert.equal(response.status, 403);
});