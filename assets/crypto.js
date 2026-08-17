/*!
 * EzJournal — envelope crypto (SPEC §10.2).
 *
 * AES-256-GCM via WebCrypto, key derivation via EzArgon2 (argon2id).
 * Engine-agnostic: works in browsers and in Node (>=19, global crypto).
 * Exposes `globalThis.EzCrypto`. Requires assets/argon2.js to be loaded first.
 *
 * Envelope format:
 * {
 *   "v": 1,
 *   "alg": "AES-256-GCM",
 *   "kdf": { "id": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "<b64>" },
 *   "wrappedKey": "<b64>",   // content key, AES-GCM-wrapped by the vault key
 *   "wrapNonce": "<b64>",    // 96-bit nonce for the wrap
 *   "nonce": "<b64>",        // 96-bit nonce for the content
 *   "ct": "<b64>"            // AES-GCM ciphertext of the UTF-8 JSON payload
 * }
 *
 * Decrypt flow: passphrase → argon2id(vault salt/params) → 32-byte vault key
 * → unwrap content key → decrypt ct → JSON payload {title, body, date, tags}.
 * A wrong passphrase surfaces as a GCM authentication failure (code
 * AUTH_FAILED) — never a partial render.
 */
(function (g) {
  'use strict';

  var subtle = g.crypto && g.crypto.subtle ? g.crypto.subtle : null;

  /* ---------------- base64 / utf-8 helpers (browser + Node) ---------------- */

  var B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

  function bytesToB64(u8) {
    if (typeof btoa === 'function') {
      var s = '';
      for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
      return btoa(s);
    }
    return Buffer.from(u8).toString('base64');
  }

  function b64ToBytes(s) {
    if (typeof s !== 'string' || !B64_RE.test(s) || s.length % 4 !== 0) {
      throw makeError('BAD_ENVELOPE', 'invalid base64');
    }
    if (typeof atob === 'function') {
      var bin = atob(s);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return new Uint8Array(Buffer.from(s, 'base64'));
  }

  function utf8Encode(s) { return new TextEncoder().encode(s); }
  function utf8Decode(u8) { return new TextDecoder('utf-8', { fatal: true }).decode(u8); }

  function makeError(code, message) {
    var e = new Error(message || code);
    e.code = code;
    return e;
  }

  /* ---------------- envelope validation ---------------- */

  var ENVELOPE_KEYS = ['v', 'alg', 'kdf', 'wrappedKey', 'wrapNonce', 'nonce', 'ct'];
  var KDF_KEYS = ['id', 'm', 't', 'p', 'salt'];

  function isB64(s) {
    return typeof s === 'string' && s.length > 0 && s.length % 4 === 0 && B64_RE.test(s);
  }

  /** Strict structural check. Returns true, or a string describing the problem. */
  function validateEnvelope(env) {
    if (typeof env !== 'object' || env === null || Array.isArray(env)) return 'not an object';
    var keys = Object.keys(env).sort();
    if (keys.join(',') !== ENVELOPE_KEYS.slice().sort().join(',')) {
      return 'unexpected field set: ' + keys.join(',');
    }
    if (env.v !== 1) return 'v must be 1';
    if (env.alg !== 'AES-256-GCM') return 'alg must be AES-256-GCM';
    var kdf = env.kdf;
    if (typeof kdf !== 'object' || kdf === null || Array.isArray(kdf)) return 'kdf not an object';
    var kkeys = Object.keys(kdf).sort();
    if (kkeys.join(',') !== KDF_KEYS.slice().sort().join(',')) {
      return 'unexpected kdf field set: ' + kkeys.join(',');
    }
    if (kdf.id !== 'argon2id') return 'kdf.id must be argon2id';
    if (!Number.isInteger(kdf.m) || kdf.m < 8) return 'kdf.m invalid';
    if (!Number.isInteger(kdf.t) || kdf.t < 1) return 'kdf.t invalid';
    if (!Number.isInteger(kdf.p) || kdf.p < 1) return 'kdf.p invalid';
    if (!isB64(kdf.salt)) return 'kdf.salt not base64';
    if (!isB64(env.wrappedKey)) return 'wrappedKey not base64';
    if (!isB64(env.wrapNonce)) return 'wrapNonce not base64';
    if (!isB64(env.nonce)) return 'nonce not base64';
    if (!isB64(env.ct)) return 'ct not base64';
    if (b64ToBytes(env.wrapNonce).length !== 12) return 'wrapNonce must be 12 bytes';
    if (b64ToBytes(env.nonce).length !== 12) return 'nonce must be 12 bytes';
    if (b64ToBytes(env.wrappedKey).length !== 48) return 'wrappedKey must be 48 bytes (32 + GCM tag)';
    return true;
  }

  /* ---------------- key derivation ---------------- */

  /**
   * passphrase (string) + kdf {id:'argon2id', m, t, p, salt(b64)} → Uint8Array(32).
   * onSlice(done, total) optionally reports derivation progress.
   */
  function deriveVaultKey(passphrase, kdf, onSlice) {
    if (!g.EzArgon2) return Promise.reject(makeError('NO_ARGON2', 'argon2.js not loaded'));
    if (!kdf || kdf.id !== 'argon2id') {
      return Promise.reject(makeError('BAD_KDF', 'unsupported kdf: ' + (kdf && kdf.id)));
    }
    return g.EzArgon2.argon2id({
      password: passphrase,
      salt: b64ToBytes(kdf.salt),
      m: kdf.m, t: kdf.t, p: kdf.p,
      tagLen: 32,
      onSlice: onSlice
    });
  }

  /* ---------------- AES-256-GCM ---------------- */

  function importAesKey(rawBytes, usages) {
    return subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, usages);
  }

  function aesGcmDecrypt(keyBytes, nonce, ct) {
    return importAesKey(keyBytes, ['decrypt'])
      .then(function (key) {
        return subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
      })
      .then(function (pt) { return new Uint8Array(pt); })
      .catch(function () {
        // GCM auth failure (or any subtle failure) — one clean error, no partial data
        throw makeError('AUTH_FAILED', 'Incorrect passphrase');
      });
  }

  function aesGcmEncrypt(keyBytes, nonce, pt) {
    return importAesKey(keyBytes, ['encrypt'])
      .then(function (key) {
        return subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, pt);
      })
      .then(function (ct) { return new Uint8Array(ct); });
  }

  /* ---------------- envelope operations ---------------- */

  /**
   * envelope + 32-byte vault key → decrypted JSON payload.
   * Throws { code: 'BAD_ENVELOPE' } on malformed input and
   * { code: 'AUTH_FAILED' } on a wrong key / tampered ciphertext.
   */
  function decryptEnvelope(env, vaultKey) {
    var problem = validateEnvelope(env);
    if (problem !== true) {
      return Promise.reject(makeError('BAD_ENVELOPE', 'invalid envelope: ' + problem));
    }
    if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== 32) {
      return Promise.reject(makeError('BAD_KEY', 'vault key must be 32 bytes'));
    }
    return aesGcmDecrypt(vaultKey, b64ToBytes(env.wrapNonce), b64ToBytes(env.wrappedKey))
      .then(function (contentKey) {
        if (contentKey.length !== 32) throw makeError('AUTH_FAILED', 'Incorrect passphrase');
        return aesGcmDecrypt(contentKey, b64ToBytes(env.nonce), b64ToBytes(env.ct));
      })
      .then(function (pt) {
        try {
          return JSON.parse(utf8Decode(pt));
        } catch (e) {
          throw makeError('BAD_PAYLOAD', 'decrypted payload is not valid JSON');
        }
      });
  }

  /**
   * Encrypt a JSON-serializable payload into a v1 envelope.
   * Fresh random content key and fresh random nonces on every call.
   * kdfInfo {m, t, p, salt(b64)} is recorded in the envelope so it stays
   * self-describing; it must match the parameters vaultKey was derived with.
   */
  function encryptEnvelope(payload, vaultKey, kdfInfo) {
    if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== 32) {
      return Promise.reject(makeError('BAD_KEY', 'vault key must be 32 bytes'));
    }
    var contentKey = new Uint8Array(32);
    var wrapNonce = new Uint8Array(12);
    var nonce = new Uint8Array(12);
    g.crypto.getRandomValues(contentKey);
    g.crypto.getRandomValues(wrapNonce);
    g.crypto.getRandomValues(nonce);
    var pt = utf8Encode(JSON.stringify(payload));
    return Promise.all([
      aesGcmEncrypt(vaultKey, wrapNonce, contentKey),
      aesGcmEncrypt(contentKey, nonce, pt)
    ]).then(function (r) {
      return {
        v: 1,
        alg: 'AES-256-GCM',
        kdf: { id: 'argon2id', m: kdfInfo.m, t: kdfInfo.t, p: kdfInfo.p, salt: kdfInfo.salt },
        wrappedKey: bytesToB64(r[0]),
        wrapNonce: bytesToB64(wrapNonce),
        nonce: bytesToB64(nonce),
        ct: bytesToB64(r[1])
      };
    });
  }

  g.EzCrypto = {
    validateEnvelope: validateEnvelope, // true, or a string describing the problem
    deriveVaultKey: deriveVaultKey,
    decryptEnvelope: decryptEnvelope,
    encryptEnvelope: encryptEnvelope,
    b64ToBytes: b64ToBytes,
    bytesToB64: bytesToB64
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
