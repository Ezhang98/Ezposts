# /assets/fonts — vendored webfonts

The theme declares `@font-face` rules (in `assets/app.css`) for three
families, all pointing at woff2 files in this directory. **Until these files
are vendored, the site still works** — every rule uses `font-display: swap`
and the font stacks fall back to system fonts (Segoe UI / Verdana for
display, Consolas / Courier New for mono).

## Exactly which files to place here

| File name (exact)          | Family          | Weight | Used for |
|----------------------------|-----------------|--------|----------|
| `orbitron-500.woff2`       | Orbitron        | 500    | nav links, small display text |
| `orbitron-700.woff2`       | Orbitron        | 700    | post titles, buttons, widget headers |
| `orbitron-900.woff2`       | Orbitron        | 900    | site title |
| `rajdhani-400.woff2`       | Rajdhani        | 400    | body text |
| `rajdhani-500.woff2`       | Rajdhani        | 500    | body emphasis |
| `rajdhani-600.woff2`       | Rajdhani        | 600    | strong text |
| `rajdhani-700.woff2`       | Rajdhani        | 700    | headings inside posts |
| `sharetechmono-400.woff2`  | Share Tech Mono | 400    | date headers, metadata, inputs, footer |

Latin subset is sufficient. Keep the file names exactly as above — they are
referenced from `app.css` relative to that stylesheet (`fonts/<name>.woff2`).

## Where to get them

All three families are open licensed (Orbitron and Share Tech Mono: SIL OFL;
Rajdhani: SIL OFL). Any of these sources works:

1. **google-webfonts-helper** — https://gwfh.mranftl.com/fonts
   Pick the family, select the weights above, choose "Modern Browsers"
   (woff2 only), download, rename to the file names above.
2. **Fontsource packages** — `npm pack @fontsource/orbitron
   @fontsource/rajdhani @fontsource/share-tech-mono` and copy the
   `files/*-latin-<weight>-normal.woff2` files out of the tarballs.
3. **Upstream repos** — Orbitron: https://github.com/theleagueof/orbitron ;
   Rajdhani + Share Tech Mono via https://github.com/google/fonts
   (subset/convert to woff2 yourself, e.g. with `pyftsubset --flavor=woff2`).

Do **not** hotlink Google Fonts — the whole point of this directory is that
readers make zero third-party requests.
