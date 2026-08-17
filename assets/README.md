# /assets — self-hosted runtime

Everything the site loads at runtime lives in this directory. **No CDN, no
third-party requests** (SPEC §9.4): better privacy for readers, and no outage
can break the site.

## Shipped files

| File | Purpose |
|---|---|
| `app.css` | Sci-fi theme ported from `blogger_theme/preview.html`, `--sf-*` variables kept |
| `app.js` | Renderer + hash router + private-vault unlock + sound layer |
| `argon2.js` | Argon2id (RFC 9106): pure-JS implementation (required path) + optional wasm loader |
| `crypto.js` | AES-256-GCM envelope handling per SPEC §10.2 |
| `fonts/` | Vendored woff2 fonts — see `fonts/README.md` |

## Optional vendored accelerators / sounds

These are **optional**. The site is fully functional without them — the
pure-JS Argon2id and the synthesized WebAudio bleeps are the required,
always-present implementations.

### `argon2.wasm` (optional, faster key derivation)

If present, `argon2.js` fetches `assets/argon2.wasm` and tries a **bare**
`WebAssembly.instantiate(buf, {})` expecting the phc-winner-argon2 C ABI:

```
exports: memory, malloc(n), free(ptr),
         argon2_hash(t, m, p, pwdPtr, pwdLen, saltPtr, saltLen,
                     hashPtr, hashLen, encodedPtr, encodedLen,
                     type, version) -> 0 on success
```

Build one from https://github.com/P-H-C/phc-winner-argon2 with a
standalone-wasm toolchain (e.g. `emcc -s STANDALONE_WASM=1 -s EXPORTED_FUNCTIONS=_argon2_hash,_malloc,_free`
or wasi-sdk). Emscripten builds that need their JS glue (such as
argon2-browser's `argon2.wasm`) will fail the bare instantiation — that is
fine; the loader silently falls back to pure JS. If you vendor a wasm build,
**verify parity first**: derive with the wasm and with `EzArgon2.argon2Sync`
for the same inputs and compare bytes (a mismatch means unopenable posts,
SPEC §10.6).

### `arwes-bleeps.js` (optional, ARWES sound package)

If present, `app.js` dynamically imports `assets/arwes-bleeps.js` and uses it
instead of the synthesized bleeps. It must be an ES module exporting
`createSfx(opts)` (or a default export) returning
`{hover, click, intro, typeStart, typeStop}` functions; `opts.isEnabled()`
tells the adapter whether sound is currently on and unlocked.

To vendor the real ARWES sounds, download the `@arwes/bleeps` ESM build plus
the four sound files (`click`, `intro`, `type` as webm/mp3) from a pinned
ARWES release (the prototype used `1.0.0-next.25020502` via jsDelivr), place
them here, and write `arwes-bleeps.js` as a small adapter that maps the bleeps
manager onto the five functions above. Failure to load at runtime is always
safe — the synthesized fallback remains.
