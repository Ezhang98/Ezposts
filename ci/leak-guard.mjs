#!/usr/bin/env node
/*
 * EzJournal leak guard (SPEC §10.4) — CI backstop against plaintext (or any
 * unexpected file) ever reaching the public repo's history.
 *
 * Fails the build when:
 *   1. any file under /private/ (except private/manifest.json) does not parse
 *      as a valid v1 encryption envelope (strict field set, all base64), or
 *      private/manifest.json is not a valid manifest, or
 *   2. any file added/modified by this push is outside the allowlist.
 *
 * Modes:
 *   CI (default): diffs BEFORE_SHA..AFTER_SHA (from the push event) via git.
 *                 A missing/all-zero BEFORE_SHA (new branch, force push)
 *                 falls back to checking every file in AFTER_SHA.
 *   --local:      no git needed; scans the working tree instead. Useful for
 *                 running the same checks before pushing.
 */
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const SITE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const LOCAL = process.argv.includes('--local');

/* ---------------- allowlist ---------------- */

const ALLOW = [
  /^index\.html$/,
  /^assets\/.+$/,
  /^index\.json$/,
  /^posts\/.+$/,
  /^private\/.+$/,
  /^README\.md$/,
  /^\.github\/.+$/,
  /^ci\/.+$/,
  /^test\/.+$/,          // the site's own test suite (run.js, vectors)
  /^\.nojekyll$/
];

function allowed(file) {
  return ALLOW.some((re) => re.test(file));
}

/* ---------------- envelope / manifest validation ----------------
 * Deliberately self-contained (no imports from assets/) so a compromised
 * or broken assets/crypto.js cannot weaken the CI check.
 */

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const b64len = (s) => Buffer.from(s, 'base64').length;
const isB64 = (s) => typeof s === 'string' && s.length > 0 && s.length % 4 === 0 && B64_RE.test(s);

function envelopeProblem(text) {
  let env;
  try { env = JSON.parse(text); } catch { return 'not valid JSON'; }
  if (typeof env !== 'object' || env === null || Array.isArray(env)) return 'not a JSON object';
  const keys = Object.keys(env).sort().join(',');
  const expected = ['alg', 'ct', 'kdf', 'nonce', 'v', 'wrapNonce', 'wrappedKey'].join(',');
  if (keys !== expected) return `unexpected field set [${keys}]`;
  if (env.v !== 1) return 'v must be 1';
  if (env.alg !== 'AES-256-GCM') return 'alg must be "AES-256-GCM"';
  const kdf = env.kdf;
  if (typeof kdf !== 'object' || kdf === null || Array.isArray(kdf)) return 'kdf is not an object';
  const kkeys = Object.keys(kdf).sort().join(',');
  if (kkeys !== ['id', 'm', 'p', 'salt', 't'].join(',')) return `unexpected kdf field set [${kkeys}]`;
  if (kdf.id !== 'argon2id') return 'kdf.id must be "argon2id"';
  if (!Number.isInteger(kdf.m) || kdf.m < 8) return 'kdf.m invalid';
  if (!Number.isInteger(kdf.t) || kdf.t < 1) return 'kdf.t invalid';
  if (!Number.isInteger(kdf.p) || kdf.p < 1) return 'kdf.p invalid';
  if (!isB64(kdf.salt)) return 'kdf.salt is not base64';
  for (const f of ['wrappedKey', 'wrapNonce', 'nonce', 'ct']) {
    if (!isB64(env[f])) return `${f} is not base64`;
  }
  if (b64len(env.wrapNonce) !== 12) return 'wrapNonce must decode to 12 bytes';
  if (b64len(env.nonce) !== 12) return 'nonce must decode to 12 bytes';
  if (b64len(env.wrappedKey) !== 48) return 'wrappedKey must decode to 48 bytes';
  if (b64len(env.ct) < 16) return 'ct shorter than a GCM tag';
  return null;
}

function manifestProblem(text) {
  let man;
  try { man = JSON.parse(text); } catch { return 'not valid JSON'; }
  if (typeof man !== 'object' || man === null || Array.isArray(man)) return 'not a JSON object';
  const keys = Object.keys(man).sort().join(',');
  if (keys !== ['kdf', 'params', 'salt', 'version'].join(',')) return `unexpected field set [${keys}]`;
  if (man.version !== 1) return 'version must be 1';
  if (man.kdf !== 'argon2id') return 'kdf must be "argon2id"';
  if (!isB64(man.salt)) return 'salt is not base64';
  const p = man.params;
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return 'params is not an object';
  if (Object.keys(p).sort().join(',') !== 'm,p,t') return 'params must be exactly {m, t, p}';
  if (![p.m, p.t, p.p].every(Number.isInteger)) return 'params must be integers';
  return null;
}

/* ---------------- file enumeration ---------------- */

function git(...args) {
  return execFileSync('git', args, { cwd: SITE, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function listLocal() {
  const out = [];
  const skip = new Set(['.git', 'node_modules']);
  (function walk(dir, rel) {
    for (const name of fs.readdirSync(dir)) {
      if (skip.has(name)) continue;
      const abs = path.join(dir, name);
      const r = rel ? rel + '/' + name : name;
      if (fs.statSync(abs).isDirectory()) walk(abs, r);
      else out.push(r);
    }
  })(SITE, '');
  return out;
}

function main() {
  const failures = [];
  let changed, readFile, allFiles;

  if (LOCAL) {
    allFiles = listLocal();
    changed = allFiles;
    readFile = (f) => fs.readFileSync(path.join(SITE, f), 'utf8');
    console.log(`leak-guard --local: checking ${allFiles.length} working-tree files`);
  } else {
    const before = process.env.BEFORE_SHA || '';
    const after = process.env.AFTER_SHA || 'HEAD';
    allFiles = git('ls-tree', '-r', '--name-only', after).split('\n').filter(Boolean);
    if (!before || /^0+$/.test(before)) {
      console.log(`leak-guard: no usable before-SHA — checking all ${allFiles.length} files at ${after}`);
      changed = allFiles;
    } else {
      changed = git('diff', '--name-only', '--diff-filter=ACMR', before, after)
        .split('\n').filter(Boolean);
      console.log(`leak-guard: ${changed.length} file(s) added/modified in ${before.slice(0, 8)}..${String(after).slice(0, 8)}`);
    }
    readFile = (f) => git('show', `${after}:${f}`);
  }

  // 1. allowlist — every added/modified file must match
  for (const f of changed) {
    if (!allowed(f)) failures.push(`file outside allowlist: ${f}`);
  }

  // 2. every file under private/ at the checked revision must be a valid
  //    envelope (manifest.json excepted, but still schema-checked).
  //    Checking all of them — not just the changed ones — means a bad file
  //    can never survive by riding along quietly.
  for (const f of allFiles.filter((x) => x.startsWith('private/'))) {
    let text;
    try { text = readFile(f); } catch (e) { failures.push(`${f}: unreadable (${e.message})`); continue; }
    if (f === 'private/manifest.json') {
      const p = manifestProblem(text);
      if (p) failures.push(`${f}: invalid manifest — ${p}`);
    } else if (f.endsWith('.enc')) {
      const p = envelopeProblem(text);
      if (p) failures.push(`${f}: NOT a valid envelope — ${p} — possible plaintext leak`);
    } else {
      failures.push(`${f}: unexpected file type under private/ (only manifest.json and *.enc allowed)`);
    }
  }

  if (failures.length) {
    console.error('\nLEAK GUARD FAILED:');
    for (const f of failures) console.error('  ✗ ' + f);
    console.error('\nRefusing this push. Nothing under /private/ may be readable, and');
    console.error('no file outside the published-site allowlist may be added.');
    process.exit(1);
  }
  console.log('leak-guard: OK');
}

main();
