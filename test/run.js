#!/usr/bin/env node
/*
 * EzJournal site test runner — plain Node, no npm dependencies.
 *
 *   node test/run.js          run everything (includes full-parameter timing)
 *   node test/run.js --fast   skip the full-parameter m=65536 vectors/timing
 *
 * Verifies:
 *   1. Blake2b against Node's OpenSSL blake2b512 + fixed vectors
 *   2. Pure-JS Argon2 (d/i/id) against every known-answer vector in
 *      test/argon2-vectors.json
 *   3. AES-256-GCM envelope round-trip through the exact decrypt path the
 *      site uses (assets/crypto.js), including wrong-passphrase behavior
 *   4. The checked-in /private/ fixtures decrypt with the dev passphrase
 *      (full KDF params) — also reports the argon2id derivation time
 */
'use strict';

const path = require('path');
const fs = require('fs');
const nodeCrypto = require('crypto');

const SITE = path.join(__dirname, '..');
require(path.join(SITE, 'assets', 'argon2.js'));
require(path.join(SITE, 'assets', 'crypto.js'));

const { EzArgon2, EzCrypto } = globalThis;
const FAST = process.argv.includes('--fast');

let passed = 0, failed = 0;
function ok(name, cond, detail) {
  if (cond) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.error('  FAIL ' + name + (detail ? ' — ' + detail : '')); }
}
const hex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

async function main() {
  /* ---------------- 1. Blake2b ---------------- */
  console.log('[1] Blake2b');
  ok('blake2b-512("abc")',
    hex(EzArgon2.blake2b(new TextEncoder().encode('abc'), 64)) ===
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1' +
    '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
  ok('blake2b-512("")',
    hex(EzArgon2.blake2b(new Uint8Array(0), 64)) ===
    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419' +
    'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce');
  // Cross-check against OpenSSL for many lengths (including >128-byte inputs)
  let cross = true, crossDetail = '';
  try {
    nodeCrypto.createHash('blake2b512');
    for (const len of [0, 1, 3, 63, 64, 65, 127, 128, 129, 255, 256, 1000, 4096]) {
      const data = nodeCrypto.randomBytes(len);
      const want = nodeCrypto.createHash('blake2b512').update(data).digest('hex');
      const got = hex(EzArgon2.blake2b(new Uint8Array(data), 64));
      if (want !== got) { cross = false; crossDetail = 'len=' + len; break; }
    }
    ok('blake2b vs OpenSSL (13 random lengths)', cross, crossDetail);
  } catch (e) {
    console.log('  skip blake2b OpenSSL cross-check (no blake2b512 in this build)');
  }

  /* ---------------- 2. Argon2 known-answer vectors ---------------- */
  console.log('[2] Argon2 known-answer vectors' + (FAST ? ' (--fast: skipping m=65536)' : ''));
  const TYPE = { argon2d: 0, argon2i: 1, argon2id: 2 };
  const vecFile = JSON.parse(fs.readFileSync(path.join(__dirname, 'argon2-vectors.json'), 'utf8'));
  for (const v of vecFile.vectors) {
    if (FAST && v.m > 8192) { console.log('  skip ' + v.name); continue; }
    const opts = {
      password: v.passwordHex ? fromHex(v.passwordHex) : v.password,
      salt: v.saltHex ? fromHex(v.saltHex) : v.salt,
      m: v.m, t: v.t, p: v.p,
      tagLen: v.tagLen,
      type: TYPE[v.type]
    };
    if (v.secretHex) opts.secret = fromHex(v.secretHex);
    if (v.adHex) opts.ad = fromHex(v.adHex);
    const t0 = Date.now();
    const out = EzArgon2.argon2Sync(opts);
    const ms = Date.now() - t0;
    ok(v.name + ' (' + ms + ' ms)', hex(out) === v.expectedHex, 'got ' + hex(out));
  }

  /* ---------------- 3. Envelope round-trip ---------------- */
  console.log('[3] AES-256-GCM envelope round-trip (site decrypt path)');
  {
    const kdf = {
      id: 'argon2id', m: 1024, t: 2, p: 1,
      salt: Buffer.from(nodeCrypto.randomBytes(16)).toString('base64')
    };
    const payload = {
      title: 'Round-trip test', body: 'hello **world**',
      date: '2026-08-14', tags: ['test']
    };
    const vaultKey = await EzCrypto.deriveVaultKey('test passphrase', kdf);
    ok('derived key is 32 bytes', vaultKey.length === 32);
    const env = await EzCrypto.encryptEnvelope(payload, vaultKey, kdf);
    ok('envelope validates', EzCrypto.validateEnvelope(env) === true);
    const back = await EzCrypto.decryptEnvelope(env, vaultKey);
    ok('payload round-trips', JSON.stringify(back) === JSON.stringify(payload));
    // wrong passphrase → clean auth failure, never partial output
    const wrongKey = await EzCrypto.deriveVaultKey('wrong passphrase', kdf);
    let threw = null;
    try { await EzCrypto.decryptEnvelope(env, wrongKey); } catch (e) { threw = e; }
    ok('wrong passphrase throws AUTH_FAILED', threw !== null && threw.code === 'AUTH_FAILED');
    // tampered ciphertext → auth failure
    const tampered = JSON.parse(JSON.stringify(env));
    const ctBytes = Buffer.from(tampered.ct, 'base64');
    ctBytes[0] ^= 0xff;
    tampered.ct = ctBytes.toString('base64');
    threw = null;
    try { await EzCrypto.decryptEnvelope(tampered, vaultKey); } catch (e) { threw = e; }
    ok('tampered ct throws AUTH_FAILED', threw !== null && threw.code === 'AUTH_FAILED');
  }

  /* ---------------- 4. Checked-in fixtures + full-param timing ---------------- */
  const manifestPath = path.join(SITE, 'private', 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.log('[4] skip fixtures (private/manifest.json missing — run ci/make-fixtures.mjs)');
  } else if (FAST) {
    console.log('[4] skip fixtures (--fast)');
  } else {
    console.log('[4] Private fixtures (full KDF params)');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const kdf = {
      id: manifest.kdf, salt: manifest.salt,
      m: manifest.params.m, t: manifest.params.t, p: manifest.params.p
    };
    ok('manifest declares argon2id m=65536 t=3 p=1',
      kdf.id === 'argon2id' && kdf.m === 65536 && kdf.t === 3 && kdf.p === 1);
    const t0 = Date.now();
    const vaultKey = await EzCrypto.deriveVaultKey(
      'correct horse battery staple example vector', kdf);
    const deriveMs = Date.now() - t0;
    console.log('  argon2id full-param derivation (m=65536 KiB, t=3, p=1): ' + deriveMs + ' ms');

    const indexEnv = JSON.parse(fs.readFileSync(path.join(SITE, 'private', 'index.enc'), 'utf8'));
    ok('index.enc validates as envelope', EzCrypto.validateEnvelope(indexEnv) === true);
    const list = await EzCrypto.decryptEnvelope(indexEnv, vaultKey);
    ok('index.enc decrypts to a non-empty array', Array.isArray(list) && list.length > 0);
    for (const item of list) {
      const postPath = path.join(SITE, 'private', item.id + '.enc');
      ok('post file exists for id ' + item.id, fs.existsSync(postPath));
      const postEnv = JSON.parse(fs.readFileSync(postPath, 'utf8'));
      ok(item.id + '.enc validates as envelope', EzCrypto.validateEnvelope(postEnv) === true);
      const post = await EzCrypto.decryptEnvelope(postEnv, vaultKey);
      ok(item.id + '.enc decrypts with title/body/date/tags',
        typeof post.title === 'string' && typeof post.body === 'string' &&
        typeof post.date === 'string' && Array.isArray(post.tags));
    }
    // wrong passphrase on the real fixtures
    const wrongKey = await EzCrypto.deriveVaultKey('incorrect horse', { ...kdf, m: 1024 });
    let threw = null;
    try { await EzCrypto.decryptEnvelope(indexEnv, wrongKey); } catch (e) { threw = e; }
    ok('fixtures reject a wrong key cleanly', threw !== null && threw.code === 'AUTH_FAILED');
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
