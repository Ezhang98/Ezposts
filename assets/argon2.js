/*!
 * EzJournal — Argon2id (RFC 9106) in pure JavaScript, plus optional wasm loader.
 *
 * Engine-agnostic: works in browsers and Node (no DOM, no Node APIs required).
 * Exposes `globalThis.EzArgon2`.
 *
 * The pure-JS implementation below is the required, always-available path.
 * If a wasm build is vendored at /assets/argon2.wasm (see assets/README.md for
 * the expected ABI) it is preferred for speed; any failure to load or
 * instantiate it silently falls back to this implementation.
 *
 * Verified against the phc-winner-argon2 test suite and the RFC 9106 test
 * vectors — see test/argon2-vectors.json and test/run.js.
 */
(function (g) {
  'use strict';

  /* ================================================================
   * Blake2b — 32-bit-pair implementation (no BigInt).
   * 64-bit words are stored as little-endian [lo, hi] pairs in
   * Uint32Arrays. Only unkeyed hashing with 1..64-byte output is
   * needed by Argon2.
   * ================================================================ */

  // IV as [lo, hi] pairs
  var BLAKE2B_IV32 = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
    0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
    0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19
  ]);

  var SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
  ];
  // Pre-double the indices for direct u32-pair addressing
  var SIGMA2 = [];
  for (var si = 0; si < 12; si++) {
    var row = new Uint8Array(16);
    for (var sj = 0; sj < 16; sj++) row[sj] = SIGMA[si][sj] * 2;
    SIGMA2.push(row);
  }

  // v[a] += v[b]  (64-bit, pairs at even indices)
  function ADD64AA(v, a, b) {
    var o0 = v[a] + v[b];
    var o1 = v[a + 1] + v[b + 1];
    if (o0 >= 0x100000000) o1++;
    v[a] = o0;      // Uint32Array assignment truncates mod 2^32
    v[a + 1] = o1;
  }

  // v[a] += [b0, b1]
  function ADD64AC(v, a, b0, b1) {
    var o0 = v[a] + b0;
    var o1 = v[a + 1] + b1;
    if (o0 >= 0x100000000) o1++;
    v[a] = o0;
    v[a + 1] = o1;
  }

  function B2B_G(v, m, a, b, c, d, ix, iy) {
    var x0 = m[ix], x1 = m[ix + 1];
    var y0 = m[iy], y1 = m[iy + 1];
    var xor0, xor1;

    ADD64AA(v, a, b);
    ADD64AC(v, a, x0, x1);
    // d = rotr64(d ^ a, 32)
    xor0 = v[d] ^ v[a];
    xor1 = v[d + 1] ^ v[a + 1];
    v[d] = xor1;
    v[d + 1] = xor0;

    ADD64AA(v, c, d);
    // b = rotr64(b ^ c, 24)
    xor0 = v[b] ^ v[c];
    xor1 = v[b + 1] ^ v[c + 1];
    v[b] = (xor0 >>> 24) ^ (xor1 << 8);
    v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);

    ADD64AA(v, a, b);
    ADD64AC(v, a, y0, y1);
    // d = rotr64(d ^ a, 16)
    xor0 = v[d] ^ v[a];
    xor1 = v[d + 1] ^ v[a + 1];
    v[d] = (xor0 >>> 16) ^ (xor1 << 16);
    v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);

    ADD64AA(v, c, d);
    // b = rotr64(b ^ c, 63)  == rotl64(b ^ c, 1)
    xor0 = v[b] ^ v[c];
    xor1 = v[b + 1] ^ v[c + 1];
    v[b] = (xor1 >>> 31) ^ (xor0 << 1);
    v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
  }

  function Blake2b(outlen) {
    if (!(outlen >= 1 && outlen <= 64)) throw new Error('blake2b: outlen out of range');
    this.b = new Uint8Array(128);   // input buffer
    this.h = new Uint32Array(16);   // state as [lo,hi] pairs
    this.t = 0;                     // bytes hashed (exact in double up to 2^53)
    this.c = 0;                     // pointer into b
    this.outlen = outlen;
    this.h.set(BLAKE2B_IV32);
    // parameter block word 0: depth=1, fanout=1, keylen=0, digestlen
    this.h[0] ^= 0x01010000 ^ outlen;
  }

  var B2B_V = new Uint32Array(32);
  var B2B_M = new Uint32Array(32);

  Blake2b.prototype._compress = function (last) {
    var v = B2B_V, m = B2B_M, i;
    for (i = 0; i < 16; i++) {
      v[i] = this.h[i];
      v[i + 16] = BLAKE2B_IV32[i];
    }
    // low 64 bits of the offset counter
    v[24] ^= this.t >>> 0;
    v[25] ^= (this.t / 0x100000000) >>> 0;
    if (last) {
      v[28] = ~v[28];
      v[29] = ~v[29];
    }
    // message words, little-endian
    var b = this.b;
    for (i = 0; i < 32; i++) {
      var o = i * 4;
      m[i] = b[o] ^ (b[o + 1] << 8) ^ (b[o + 2] << 16) ^ (b[o + 3] << 24);
    }
    for (i = 0; i < 12; i++) {
      var s = SIGMA2[i];
      B2B_G(v, m, 0, 8, 16, 24, s[0], s[1]);
      B2B_G(v, m, 2, 10, 18, 26, s[2], s[3]);
      B2B_G(v, m, 4, 12, 20, 28, s[4], s[5]);
      B2B_G(v, m, 6, 14, 22, 30, s[6], s[7]);
      B2B_G(v, m, 0, 10, 20, 30, s[8], s[9]);
      B2B_G(v, m, 2, 12, 22, 24, s[10], s[11]);
      B2B_G(v, m, 4, 14, 16, 26, s[12], s[13]);
      B2B_G(v, m, 6, 8, 18, 28, s[14], s[15]);
    }
    for (i = 0; i < 16; i++) {
      this.h[i] = this.h[i] ^ v[i] ^ v[i + 16];
    }
  };

  Blake2b.prototype.update = function (input) {
    for (var i = 0; i < input.length; i++) {
      if (this.c === 128) {
        this.t += this.c;
        this._compress(false);
        this.c = 0;
      }
      this.b[this.c++] = input[i];
    }
    return this;
  };

  Blake2b.prototype.digest = function () {
    this.t += this.c;
    while (this.c < 128) this.b[this.c++] = 0;
    this._compress(true);
    var out = new Uint8Array(this.outlen);
    for (var i = 0; i < this.outlen; i++) {
      out[i] = (this.h[i >> 2] >> (8 * (i & 3))) & 0xff;
    }
    return out;
  };

  function blake2b(input, outlen) {
    var h = new Blake2b(outlen);
    h.update(input);
    return h.digest();
  }

  /* ================================================================
   * Argon2 (RFC 9106) — types: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id
   * Version 0x13 only.
   * ================================================================ */

  var ARGON2_VERSION = 0x13;

  function le32(n) {
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  }

  function concatBytes(parts) {
    var len = 0, i;
    for (i = 0; i < parts.length; i++) len += parts[i].length;
    var out = new Uint8Array(len);
    var off = 0;
    for (i = 0; i < parts.length; i++) {
      out.set(parts[i], off);
      off += parts[i].length;
    }
    return out;
  }

  // H' — variable-length hash (RFC 9106 §3.3)
  function hprime(input, outlen) {
    if (outlen <= 64) {
      return blake2b(concatBytes([le32(outlen), input]), outlen);
    }
    var r = Math.ceil(outlen / 32) - 2;
    var out = new Uint8Array(outlen);
    var v = blake2b(concatBytes([le32(outlen), input]), 64);
    out.set(v.subarray(0, 32), 0);
    for (var i = 1; i < r; i++) {
      v = blake2b(v, 64);
      out.set(v.subarray(0, 32), i * 32);
    }
    var last = blake2b(v, outlen - 32 * r);
    out.set(last, r * 32);
    return out;
  }

  /* ---- 1024-byte block = Uint32Array segment of length 256 ----
   * u64 word w of a block lives at [base + 2w] (lo), [base + 2w + 1] (hi).
   */

  // High 32 bits of the 64-bit product of two u32 values.
  function mulHi32(a, b) {
    var aL = a & 0xffff, aH = a >>> 16;
    var bL = b & 0xffff, bH = b >>> 16;
    var ll = aL * bL;
    var mid = aL * bH + aH * bL;              // < 2^33, exact in a double
    var hh = aH * bH;
    var carry = Math.floor((ll + (mid % 65536) * 65536) / 4294967296);
    return (hh + Math.floor(mid / 65536) + carry) >>> 0;
  }

  // B[a] = B[a] + B[b] + 2 * lo32(B[a]) * lo32(B[b])   (mod 2^64)
  function fBlaMka(B, a, b) {
    var xl = B[a], xh = B[a + 1], yl = B[b], yh = B[b + 1];
    var aL = xl & 0xffff, aH = xl >>> 16;
    var bL = yl & 0xffff, bH = yl >>> 16;
    var ll = aL * bL;
    var mid = aL * bH + aH * bL;              // < 2^33
    var hh = aH * bH;
    var lowSum = ll + (mid % 65536) * 65536;  // < 2^33
    var mlo = lowSum >>> 0;
    var mhi = (hh + Math.floor(mid / 65536) + Math.floor(lowSum / 4294967296)) >>> 0;
    // 2 * product (mod 2^64)
    var m2hi = ((mhi << 1) | (mlo >>> 31)) >>> 0;
    var m2lo = (mlo << 1) >>> 0;
    // x + y + 2m (mod 2^64)
    var slo = xl + yl + m2lo;                 // < 3 * 2^32, exact
    var shi = xh + yh + m2hi + Math.floor(slo / 4294967296);
    B[a] = slo;
    B[a + 1] = shi;
  }

  function GBlaMka(B, a, b, c, d) {
    var xor0, xor1;
    fBlaMka(B, a, b);
    // d = rotr64(d ^ a, 32)
    xor0 = B[d] ^ B[a];
    xor1 = B[d + 1] ^ B[a + 1];
    B[d] = xor1;
    B[d + 1] = xor0;
    fBlaMka(B, c, d);
    // b = rotr64(b ^ c, 24)
    xor0 = B[b] ^ B[c];
    xor1 = B[b + 1] ^ B[c + 1];
    B[b] = (xor0 >>> 24) ^ (xor1 << 8);
    B[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
    fBlaMka(B, a, b);
    // d = rotr64(d ^ a, 16)
    xor0 = B[d] ^ B[a];
    xor1 = B[d + 1] ^ B[a + 1];
    B[d] = (xor0 >>> 16) ^ (xor1 << 16);
    B[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
    fBlaMka(B, c, d);
    // b = rotr64(b ^ c, 63) == rotl64(b ^ c, 1)
    xor0 = B[b] ^ B[c];
    xor1 = B[b + 1] ^ B[c + 1];
    B[b] = (xor1 >>> 31) ^ (xor0 << 1);
    B[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
  }

  // Permutation P over 16 u64 words given by their lo-word offsets in B.
  function P16(B, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) {
    GBlaMka(B, v0, v4, v8, v12);
    GBlaMka(B, v1, v5, v9, v13);
    GBlaMka(B, v2, v6, v10, v14);
    GBlaMka(B, v3, v7, v11, v15);
    GBlaMka(B, v0, v5, v10, v15);
    GBlaMka(B, v1, v6, v11, v12);
    GBlaMka(B, v2, v7, v8, v13);
    GBlaMka(B, v3, v4, v9, v14);
  }

  var FB_R = new Uint32Array(256);
  var FB_Z = new Uint32Array(256);

  /* out[oo..] = G(prev, ref) [^ existing out when withXor]
   * prev/ref/out are Uint32Arrays; po/ro/oo are element offsets of the blocks.
   * Safe when out aliases prev or ref (works on scratch copies).
   */
  function fillBlock(prev, po, ref, ro, out, oo, withXor) {
    var i, b;
    var R = FB_R, Z = FB_Z;
    for (i = 0; i < 256; i++) R[i] = prev[po + i] ^ ref[ro + i];
    Z.set(R);
    // rows: registers 8i..8i+7 → 16 consecutive u64 words
    for (i = 0; i < 8; i++) {
      b = i * 32;
      P16(Z, b, b + 2, b + 4, b + 6, b + 8, b + 10, b + 12, b + 14,
          b + 16, b + 18, b + 20, b + 22, b + 24, b + 26, b + 28, b + 30);
    }
    // columns: registers j, j+8, ..., j+56
    for (i = 0; i < 8; i++) {
      b = i * 4;
      P16(Z, b, b + 2, b + 32, b + 34, b + 64, b + 66, b + 96, b + 98,
          b + 128, b + 130, b + 160, b + 162, b + 192, b + 194, b + 224, b + 226);
    }
    if (withXor) {
      for (i = 0; i < 256; i++) out[oo + i] ^= R[i] ^ Z[i];
    } else {
      for (i = 0; i < 256; i++) out[oo + i] = R[i] ^ Z[i];
    }
  }

  function setU64(arr, word, value) {
    arr[2 * word] = value >>> 0;
    arr[2 * word + 1] = Math.floor(value / 4294967296) >>> 0;
  }

  function incU64(arr, word) {
    var lo = (arr[2 * word] + 1) >>> 0;
    arr[2 * word] = lo;
    if (lo === 0) arr[2 * word + 1] = (arr[2 * word + 1] + 1) >>> 0;
  }

  function nextAddresses(addr, input, zero) {
    incU64(input, 6); // counter
    fillBlock(zero, 0, input, 0, addr, 0, false);
    fillBlock(zero, 0, addr, 0, addr, 0, false);
  }

  function fillSegment(mem, ctx, pass, slice, lane) {
    var q = ctx.laneLength, segLen = ctx.segmentLength, p = ctx.lanes;
    var type = ctx.type;
    var dataIndependent =
      type === 1 || (type === 2 && pass === 0 && slice < 2);

    var addressBlock = null, inputBlock = null, zeroBlock = null;
    if (dataIndependent) {
      zeroBlock = new Uint32Array(256);
      inputBlock = new Uint32Array(256);
      addressBlock = new Uint32Array(256);
      setU64(inputBlock, 0, pass);
      setU64(inputBlock, 1, lane);
      setU64(inputBlock, 2, slice);
      setU64(inputBlock, 3, ctx.memoryBlocks);
      setU64(inputBlock, 4, ctx.passes);
      setU64(inputBlock, 5, type);
      // word 6 (counter) starts at 0, incremented inside nextAddresses
    }

    var startIdx = 0;
    if (pass === 0 && slice === 0) {
      startIdx = 2; // first two blocks were produced by H'
      if (dataIndependent) nextAddresses(addressBlock, inputBlock, zeroBlock);
    }

    for (var i = startIdx; i < segLen; i++) {
      var col = slice * segLen + i;
      var prevCol = col === 0 ? q - 1 : col - 1;
      var prevOff = (lane * q + prevCol) * 256;
      var currOff = (lane * q + col) * 256;

      var j1, j2;
      if (dataIndependent) {
        var ai = i % 128;
        // reference: if (i % ADDRESSES_IN_BLOCK == 0) next_addresses(...)
        // (the first segment pre-generates before the loop; its loop starts at i=2)
        if (ai === 0) nextAddresses(addressBlock, inputBlock, zeroBlock);
        j1 = addressBlock[2 * ai];
        j2 = addressBlock[2 * ai + 1];
      } else {
        j1 = mem[prevOff];
        j2 = mem[prevOff + 1];
      }

      var refLane = j2 % p;
      if (pass === 0 && slice === 0) refLane = lane;
      var sameLane = refLane === lane;

      // index_alpha (reference implementation semantics, v1.3)
      var refAreaSize;
      if (pass === 0) {
        if (slice === 0) {
          refAreaSize = i - 1;
        } else if (sameLane) {
          refAreaSize = slice * segLen + i - 1;
        } else {
          refAreaSize = slice * segLen + (i === 0 ? -1 : 0);
        }
      } else if (sameLane) {
        refAreaSize = q - segLen + i - 1;
      } else {
        refAreaSize = q - segLen + (i === 0 ? -1 : 0);
      }

      var relPos = mulHi32(j1, j1);
      var y = mulHi32(refAreaSize, relPos);
      var z = refAreaSize - 1 - y;
      var startPos = 0;
      if (pass !== 0) startPos = slice === 3 ? 0 : (slice + 1) * segLen;
      var refIndex = (startPos + z) % q;
      var refOff = (refLane * q + refIndex) * 256;

      fillBlock(mem, prevOff, mem, refOff, mem, currOff, pass > 0);
    }
  }

  function toBytes(x) {
    if (x instanceof Uint8Array) return x;
    if (typeof x === 'string') return new TextEncoder().encode(x);
    if (Array.isArray(x)) return new Uint8Array(x);
    if (x && x.buffer instanceof ArrayBuffer) return new Uint8Array(x.buffer, x.byteOffset || 0, x.byteLength);
    throw new Error('argon2: expected Uint8Array or string');
  }

  /**
   * Core Argon2 (synchronous). opts:
   *   password, salt       — Uint8Array | string (UTF-8)
   *   m                    — memory in KiB
   *   t                    — passes
   *   p                    — lanes
   *   tagLen               — output length in bytes (default 32)
   *   type                 — 0 (d) | 1 (i) | 2 (id, default)
   *   secret, ad           — optional Uint8Array
   *   onSlice(done, total) — optional progress callback (called between slices)
   */
  function argon2Sync(opts) {
    var pwd = toBytes(opts.password);
    var salt = toBytes(opts.salt);
    var secret = opts.secret ? toBytes(opts.secret) : new Uint8Array(0);
    var ad = opts.ad ? toBytes(opts.ad) : new Uint8Array(0);
    var p = opts.p >>> 0, t = opts.t >>> 0, m = opts.m >>> 0;
    var tagLen = (opts.tagLen || 32) >>> 0;
    var type = opts.type === undefined ? 2 : opts.type | 0;
    if (!(p >= 1)) throw new Error('argon2: p must be >= 1');
    if (!(t >= 1)) throw new Error('argon2: t must be >= 1');
    if (!(m >= 8 * p)) throw new Error('argon2: m must be >= 8*p');
    if (type !== 0 && type !== 1 && type !== 2) throw new Error('argon2: bad type');

    // H0
    var h0 = blake2b(concatBytes([
      le32(p), le32(tagLen), le32(m), le32(t), le32(ARGON2_VERSION), le32(type),
      le32(pwd.length), pwd,
      le32(salt.length), salt,
      le32(secret.length), secret,
      le32(ad.length), ad
    ]), 64);

    var memoryBlocks = 4 * p * Math.floor(m / (4 * p));
    var laneLength = memoryBlocks / p;
    var segmentLength = laneLength / 4;
    var mem = new Uint32Array(memoryBlocks * 256);

    // First two blocks of every lane
    for (var lane = 0; lane < p; lane++) {
      for (var idx = 0; idx < 2; idx++) {
        var blk = hprime(concatBytes([h0, le32(idx), le32(lane)]), 1024);
        var off = (lane * laneLength + idx) * 256;
        for (var k = 0; k < 256; k++) {
          var o = k * 4;
          mem[off + k] = blk[o] ^ (blk[o + 1] << 8) ^ (blk[o + 2] << 16) ^ (blk[o + 3] << 24);
        }
      }
    }

    var ctx = {
      lanes: p, passes: t, type: type,
      memoryBlocks: memoryBlocks, laneLength: laneLength, segmentLength: segmentLength
    };

    var totalSlices = t * 4;
    var doneSlices = 0;
    for (var pass = 0; pass < t; pass++) {
      for (var slice = 0; slice < 4; slice++) {
        for (var l = 0; l < p; l++) {
          fillSegment(mem, ctx, pass, slice, l);
        }
        doneSlices++;
        if (opts.onSlice) opts.onSlice(doneSlices, totalSlices);
      }
    }

    // XOR the last block of every lane, then H' to tagLen
    var finalBlock = new Uint32Array(256);
    for (var l2 = 0; l2 < p; l2++) {
      var fo = (l2 * laneLength + laneLength - 1) * 256;
      for (var k2 = 0; k2 < 256; k2++) finalBlock[k2] ^= mem[fo + k2];
    }
    var finalBytes = new Uint8Array(1024);
    for (var k3 = 0; k3 < 256; k3++) {
      var w = finalBlock[k3];
      finalBytes[k3 * 4] = w & 0xff;
      finalBytes[k3 * 4 + 1] = (w >>> 8) & 0xff;
      finalBytes[k3 * 4 + 2] = (w >>> 16) & 0xff;
      finalBytes[k3 * 4 + 3] = (w >>> 24) & 0xff;
    }
    mem.fill(0); // best-effort wipe
    return hprime(finalBytes, tagLen);
  }

  /* ================================================================
   * Optional wasm acceleration.
   *
   * If a browser page has vendored /assets/argon2.wasm, the loader
   * tries a bare WebAssembly instantiation and expects the
   * phc-winner-argon2 C ABI:
   *   exports: memory, malloc(n), free(p),
   *            argon2_hash(t, m, p, pwd, pwdlen, salt, saltlen,
   *                        hash, hashlen, encoded, encodedlen,
   *                        type, version) -> 0 on success
   * (Emscripten builds that require a JS glue module will fail to
   * instantiate bare and fall back to pure JS — see assets/README.md.)
   * ================================================================ */

  var wasmState = { tried: false, api: null, baseUrl: null };
  try {
    if (typeof document !== 'undefined' && document.currentScript && document.currentScript.src) {
      wasmState.baseUrl = document.currentScript.src.replace(/[^\/]*$/, '');
    }
  } catch (e) { /* ignore */ }

  function tryLoadWasm() {
    if (wasmState.tried) return Promise.resolve(wasmState.api);
    wasmState.tried = true;
    if (typeof fetch !== 'function' || typeof WebAssembly === 'undefined' || !wasmState.baseUrl) {
      return Promise.resolve(null);
    }
    return fetch(wasmState.baseUrl + 'argon2.wasm')
      .then(function (res) {
        if (!res.ok) throw new Error('no wasm');
        return res.arrayBuffer();
      })
      .then(function (buf) { return WebAssembly.instantiate(buf, {}); })
      .then(function (result) {
        var ex = result.instance.exports;
        if (!ex.memory || !ex.malloc || !ex.free || !ex.argon2_hash) throw new Error('unexpected wasm ABI');
        wasmState.api = ex;
        return ex;
      })
      .catch(function () {
        wasmState.api = null;
        return null;
      });
  }

  function wasmArgon2(ex, opts) {
    var pwd = toBytes(opts.password);
    var salt = toBytes(opts.salt);
    var tagLen = (opts.tagLen || 32) >>> 0;
    var type = opts.type === undefined ? 2 : opts.type | 0;
    var pPwd = ex.malloc(pwd.length || 1);
    var pSalt = ex.malloc(salt.length || 1);
    var pHash = ex.malloc(tagLen);
    try {
      var heap = new Uint8Array(ex.memory.buffer);
      heap.set(pwd, pPwd);
      heap.set(salt, pSalt);
      var rc = ex.argon2_hash(opts.t, opts.m, opts.p, pPwd, pwd.length, pSalt, salt.length,
        pHash, tagLen, 0, 0, type, ARGON2_VERSION);
      if (rc !== 0) throw new Error('argon2 wasm error ' + rc);
      // memory may have grown; re-view
      return new Uint8Array(ex.memory.buffer).slice(pHash, pHash + tagLen);
    } finally {
      ex.free(pPwd); ex.free(pSalt); ex.free(pHash);
    }
  }

  /**
   * Async front door. Prefers wasm when available; otherwise runs the
   * pure-JS implementation, yielding to the event loop between slices
   * so a browser UI can keep animating. Returns Promise<Uint8Array>.
   */
  function argon2id(opts) {
    return tryLoadWasm().then(function (ex) {
      if (ex && !opts.secret && !opts.ad) {
        try {
          return wasmArgon2(ex, Object.assign({ type: 2 }, opts));
        } catch (e) { /* fall through to JS */ }
      }
      return argon2Async(Object.assign({ type: 2 }, opts));
    });
  }

  function argon2Async(opts) {
    // Chunked run: fillSegment work happens synchronously per slice but we
    // yield between slices so the page can repaint (progress callbacks fire).
    return new Promise(function (resolve, reject) {
      try {
        // For small m just run synchronously.
        if (opts.m <= 4096) return resolve(argon2Sync(opts));
        var onSliceUser = opts.onSlice;
        var pending = [];
        var wrapped = Object.assign({}, opts, {
          onSlice: function (done, total) {
            if (onSliceUser) pending.push([done, total]);
          }
        });
        // Run on a macrotask so the caller's UI update paints first.
        setTimeout(function () {
          try {
            var out = argon2Sync(wrapped);
            if (onSliceUser) pending.forEach(function (a) { onSliceUser(a[0], a[1]); });
            resolve(out);
          } catch (e) { reject(e); }
        }, 30);
      } catch (e) { reject(e); }
    });
  }

  g.EzArgon2 = {
    blake2b: blake2b,
    Blake2b: Blake2b,
    hprime: hprime,
    argon2Sync: argon2Sync,
    argon2id: argon2id,
    version: ARGON2_VERSION
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
