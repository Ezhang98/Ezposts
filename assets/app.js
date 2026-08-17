/*!
 * EzJournal — site renderer, hash router, private-vault unlock, sound layer.
 *
 * Plain script, no build step, no third-party requests. Works two ways:
 *   - on index.html (has #app): full SPA — public list, archive, posts,
 *     private section
 *   - on pre-rendered posts/<slug>.html (no #app): chrome only — sound
 *     toggle + typing effects; the post text is server-rendered and fully
 *     readable without this script.
 *
 * Sound: if /assets/arwes-bleeps.js has been vendored (see assets/README.md)
 * it is preferred; otherwise the synthesized WebAudio bleeps below are the
 * required fallback. Toggle persisted in localStorage, default ON, audio
 * unlocked on first interaction.
 */
(function () {
  'use strict';

  /* ================================================================
   * Utilities
   * ================================================================ */

  function $(sel, root) { return (root || document).querySelector(sel); }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtDate(iso) {
    // Render "2026-08-14" without timezone surprises.
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || ''));
    if (!m) return esc(iso);
    var months = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
      'August', 'September', 'October', 'November', 'December'];
    var d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
    var days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return days[d.getUTCDay()] + ', ' + months[+m[2] - 1] + ' ' + (+m[3]) + ', ' + m[1];
  }

  function monthKey(iso) { return String(iso || '').slice(0, 7); }
  function monthLabel(key) {
    var m = /^(\d{4})-(\d{2})$/.exec(key);
    if (!m) return key;
    var months = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
      'August', 'September', 'October', 'November', 'December'];
    return months[+m[2] - 1] + ' ' + m[1];
  }

  function fetchJSON(url) {
    return fetch(url, { cache: 'no-cache' }).then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status + ' for ' + url);
      return res.json();
    });
  }

  var reducedMotion = typeof matchMedia === 'function' &&
    matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ================================================================
   * Minimal Markdown renderer (escapes first; only ever emits its own
   * markup). Enough for journal entries: headings, hr, blockquote,
   * fenced code, lists, bold/italic/inline code, links, paragraphs.
   * ================================================================ */

  function mdInline(s) {
    return s
      .replace(/`([^`]+)`/g, function (_, c) { return '<code>' + c + '</code>'; })
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
        '<a href="$2" rel="noopener noreferrer">$1</a>');
  }

  function mdToHtml(md) {
    var lines = String(md || '').replace(/\r\n?/g, '\n').split('\n');
    var out = [], i = 0, para = [], inList = false;

    function flushPara() {
      if (para.length) {
        out.push('<p>' + mdInline(para.join(' ')) + '</p>');
        para = [];
      }
    }
    function closeList() { if (inList) { out.push('</ul>'); inList = false; } }

    while (i < lines.length) {
      var raw = lines[i], line = esc(raw);
      if (/^```/.test(raw)) {              // fenced code
        flushPara(); closeList();
        var code = [];
        i++;
        while (i < lines.length && !/^```/.test(lines[i])) { code.push(esc(lines[i])); i++; }
        i++; // closing fence
        out.push('<pre><code>' + code.join('\n') + '</code></pre>');
        continue;
      }
      var h = /^(#{1,3})\s+(.*)$/.exec(raw);
      if (h) {
        flushPara(); closeList();
        var lvl = h[1].length;
        out.push('<h' + lvl + '>' + mdInline(esc(h[2])) + '</h' + lvl + '>');
      } else if (/^\s*([-*_])\s*\1\s*\1[\s\-*_]*$/.test(raw)) {
        flushPara(); closeList();
        out.push('<hr>');
      } else if (/^>\s?/.test(raw)) {
        flushPara(); closeList();
        out.push('<blockquote><p>' + mdInline(esc(raw.replace(/^>\s?/, ''))) + '</p></blockquote>');
      } else if (/^[-*]\s+/.test(raw)) {
        flushPara();
        if (!inList) { out.push('<ul>'); inList = true; }
        out.push('<li>' + mdInline(esc(raw.replace(/^[-*]\s+/, ''))) + '</li>');
      } else if (/^\s*$/.test(raw)) {
        flushPara(); closeList();
      } else {
        para.push(line);
      }
      i++;
    }
    flushPara(); closeList();
    return out.join('\n');
  }

  function bodyToHtml(body) {
    // Payload body may be markdown or pre-rendered HTML (SPEC §10.2 payload).
    if (/^\s*</.test(String(body || ''))) return body;
    return mdToHtml(body);
  }

  /* ================================================================
   * Sound layer — synthesized WebAudio bleeps (required fallback),
   * optionally replaced by a vendored /assets/arwes-bleeps.js.
   * ================================================================ */

  var STORE_KEY = 'scifi-sound';
  var sndEnabled = true; // default ON (carried over from the prototype)
  try { sndEnabled = localStorage.getItem(STORE_KEY) !== 'off'; } catch (e) {}
  var sndBooted = false;
  var lastHover = 0;

  var sfx = {
    hover: function () {}, click: function () {}, intro: function () {},
    typeStart: function () {}, typeStop: function () {}
  };

  function installSynthSfx() {
    var ctx = null;
    function ac() {
      if (!ctx) {
        var AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return null;
        ctx = new AC();
      }
      if (ctx.state === 'suspended') ctx.resume();
      return ctx;
    }
    function tone(freq, dur, type, vol, slideTo) {
      if (!sndEnabled) return;
      var c = ac();
      if (!c) return;
      var t = c.currentTime;
      var o = c.createOscillator();
      var gn = c.createGain();
      o.type = type || 'square';
      o.frequency.setValueAtTime(freq, t);
      if (slideTo) o.frequency.exponentialRampToValueAtTime(slideTo, t + dur);
      gn.gain.setValueAtTime(0.0001, t);
      gn.gain.exponentialRampToValueAtTime(vol || 0.04, t + 0.005);
      gn.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      o.connect(gn);
      gn.connect(c.destination);
      o.start(t);
      o.stop(t + dur + 0.02);
    }
    var typeTimer = null;
    sfx.hover = function () { tone(1320, 0.05, 'square', 0.02); };
    sfx.click = function () {
      tone(523, 0.07, 'square', 0.04, 1046);
      setTimeout(function () { tone(1567, 0.09, 'sine', 0.035); }, 60);
    };
    sfx.intro = function () {
      tone(220, 0.25, 'sawtooth', 0.025, 880);
      setTimeout(function () { tone(1318, 0.12, 'sine', 0.035); }, 220);
    };
    sfx.typeStart = function () {
      if (typeTimer) return;
      typeTimer = setInterval(function () {
        if (sndBooted) tone(2100 + Math.random() * 500, 0.018, 'square', 0.012);
      }, 34);
    };
    sfx.typeStop = function () {
      if (typeTimer) { clearInterval(typeTimer); typeTimer = null; }
    };
  }

  // Prefer a vendored ARWES bleeps adapter if present; the synthesized
  // implementation above is the always-available fallback.
  installSynthSfx();
  try {
    import('./arwes-bleeps.js').then(function (mod) {
      var make = mod.createSfx || mod.default;
      if (typeof make !== 'function') return;
      var custom = make({ isEnabled: function () { return sndEnabled && sndBooted; } });
      ['hover', 'click', 'intro', 'typeStart', 'typeStop'].forEach(function (k) {
        if (typeof custom[k] === 'function') sfx[k] = custom[k];
      });
    }).catch(function () { /* keep synthesized fallback */ });
  } catch (e) { /* environments without dynamic import keep the fallback */ }

  function interactive(el) {
    return el && el.closest && el.closest('a, button, input[type="submit"], label.sf-check');
  }
  function unlockAudio() {
    if (sndBooted) return;
    sndBooted = true;
    if (sndEnabled) sfx.intro();
  }
  document.addEventListener('pointerdown', unlockAudio);
  document.addEventListener('keydown', unlockAudio);
  document.addEventListener('touchstart', unlockAudio);
  document.addEventListener('mouseover', function (e) {
    if (!sndBooted || !sndEnabled || !interactive(e.target)) return;
    var n = Date.now();
    if (n - lastHover < 90) return;
    lastHover = n;
    sfx.hover();
  });
  document.addEventListener('click', function (e) {
    if (sndBooted && sndEnabled && interactive(e.target)) sfx.click();
  });

  function installSoundToggle() {
    var btn = document.createElement('button');
    btn.id = 'sf-sound-toggle';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Toggle sound effects');
    function paint() {
      btn.textContent = sndEnabled ? '♫ SND ON' : '✕ SND OFF';
      btn.className = sndEnabled ? 'on' : 'off';
    }
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      unlockAudio();
      sndEnabled = !sndEnabled;
      try { localStorage.setItem(STORE_KEY, sndEnabled ? 'on' : 'off'); } catch (e) {}
      paint();
      if (sndEnabled) sfx.click(); else sfx.typeStop();
    });
    paint();
    document.body.appendChild(btn);
  }

  /* ================================================================
   * Typing effect — only ever REVEALS text that is already rendered.
   * A watchdog guarantees the full text is restored even if the
   * animation is interrupted. Applied to plain-text headers only.
   * ================================================================ */

  var typeGeneration = 0;

  function typeReveal(el, delay) {
    if (reducedMotion) return;
    if (el.getAttribute('data-sf-typed')) return;
    el.setAttribute('data-sf-typed', '1');
    var full = el.textContent;
    if (!full) return;
    var gen = typeGeneration;
    var dur = Math.min(350 + full.length * 30, 2200);
    var perChar = dur / full.length;
    var shown = 0;
    var timer = null;
    function finish() {
      if (timer) { clearInterval(timer); timer = null; }
      sfx.typeStop();
      // watchdog contract: text is always fully present at the end
      if (el.textContent !== full) el.textContent = full;
    }
    setTimeout(function () {
      if (gen !== typeGeneration) { el.textContent = full; return; }
      el.textContent = '';
      sfx.typeStart();
      timer = setInterval(function () {
        if (gen !== typeGeneration) { finish(); return; }
        shown += 1 + Math.floor(Math.random() * 2);
        if (shown >= full.length) { finish(); return; }
        el.textContent = full.slice(0, shown);
      }, Math.max(perChar, 12));
      // hard watchdog: never leave text hidden, no matter what
      setTimeout(finish, dur + 250);
    }, delay || 0);
  }

  function animateHeaders(root) {
    typeGeneration++; // cancel any in-flight typers (their watchdogs restore text)
    if (reducedMotion) return;
    var els = (root || document).querySelectorAll(
      '.site-tagline span, h2.date-header span, h3.post-title, ' +
      '.sidebar-col .widget h2, .unlock-title, .decrypt-status'
    );
    var delay = 0;
    Array.prototype.forEach.call(els, function (el) {
      // only animate elements whose content is plain text
      if (el.children.length === 1 && el.children[0].tagName === 'A') el = el.children[0];
      if (el.children.length > 0) return;
      typeReveal(el, delay);
      delay = Math.min(delay + 130, 2600);
    });
  }

  /* ================================================================
   * SPA (index.html only)
   * ================================================================ */

  var app = $('#app');
  var state = {
    index: null,        // /index.json cache
    vaultKey: null,     // Uint8Array(32), memory only unless opted in
    privIndex: null,    // decrypted private index
    search: ''
  };

  var SESSION_KEY = 'ez-vault-key';

  function restoreRememberedKey() {
    try {
      var b64 = sessionStorage.getItem(SESSION_KEY);
      if (b64) {
        var k = EzCrypto.b64ToBytes(b64);
        if (k.length === 32) state.vaultKey = k;
      }
    } catch (e) {}
  }

  function forgetKey() {
    state.vaultKey = null;
    state.privIndex = null;
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
  }

  var indexPromise = null;
  function loadIndex() {
    if (!indexPromise) {
      indexPromise = fetchJSON('index.json').then(function (ix) {
        state.index = ix;
        renderArchiveWidget(ix);
        return ix;
      }).catch(function (e) {
        indexPromise = null; // allow retry on next navigation
        throw e;
      });
    }
    return indexPromise;
  }

  function setNav(route) {
    var lis = document.querySelectorAll('.site-nav li');
    Array.prototype.forEach.call(lis, function (li) {
      li.classList.toggle('selected', li.getAttribute('data-route') === route);
    });
  }

  function tagChips(tags) {
    if (!tags || !tags.length) return '';
    return '<span class="tags">' + tags.map(function (t) {
      return '<span class="tag-chip">' + esc(t) + '</span>';
    }).join('') + '</span>';
  }

  function errorPanel(title, detail) {
    return '<div class="post-outer error-panel">' +
      '<h3 class="post-title">' + esc(title) + '</h3>' +
      '<div class="post-body">' + esc(detail) + '</div></div>';
  }

  /* ---------------- public views ---------------- */

  function renderHome() {
    setNav('home');
    loadIndex().then(function (ix) {
      var posts = (ix.posts || ix).slice().sort(function (a, b) {
        return a.date < b.date ? 1 : -1;
      });
      var q = state.search.trim().toLowerCase();
      if (q) {
        posts = posts.filter(function (p) {
          return (p.title + ' ' + p.excerpt + ' ' + (p.tags || []).join(' '))
            .toLowerCase().indexOf(q) !== -1;
        });
      }
      var html = '<div class="blog-posts">';
      if (!posts.length) {
        html += '<div class="date-outer"><div class="post-outer"><div class="post-body">' +
          (q ? 'No transmissions match &quot;' + esc(q) + '&quot;.' : 'No public transmissions yet.') +
          '</div></div></div>';
      }
      posts.forEach(function (p) {
        html += '<div class="date-outer">' +
          '<h2 class="date-header"><span>' + esc(fmtDate(p.date)) + '</span></h2>' +
          '<div class="post-outer">' +
          '<h3 class="post-title"><a href="#/post/' + encodeURIComponent(p.slug) + '">' + esc(p.title) + '</a></h3>' +
          '<div class="post-body">' + esc(p.excerpt) + '</div>' +
          '<div class="post-footer">' + tagChips(p.tags) +
          ' <a href="posts/' + encodeURIComponent(p.slug) + '.html">STATIC COPY</a></div>' +
          '</div></div>';
      });
      html += '</div>';
      app.innerHTML = html;
      animateHeaders(app);
    }).catch(function (e) {
      app.innerHTML = errorPanel('Index unavailable', String(e.message || e));
    });
  }

  function renderArchive() {
    setNav('archive');
    loadIndex().then(function (ix) {
      var posts = (ix.posts || ix).slice().sort(function (a, b) {
        return a.date < b.date ? 1 : -1;
      });
      var byMonth = {};
      var order = [];
      posts.forEach(function (p) {
        var k = monthKey(p.date);
        if (!byMonth[k]) { byMonth[k] = []; order.push(k); }
        byMonth[k].push(p);
      });
      var html = '<div class="blog-posts">';
      order.forEach(function (k) {
        html += '<div class="date-outer">' +
          '<h2 class="date-header"><span>' + esc(monthLabel(k)) + '</span></h2>' +
          '<div class="post-outer"><ul style="list-style:none;padding-left:0;margin:0;">';
        byMonth[k].forEach(function (p) {
          html += '<li>▸ <a href="#/post/' + encodeURIComponent(p.slug) + '">' + esc(p.title) + '</a>' +
            ' <span class="status-line">' + esc(p.date) + '</span></li>';
        });
        html += '</ul></div></div>';
      });
      html += '</div>';
      app.innerHTML = html;
      animateHeaders(app);
    }).catch(function (e) {
      app.innerHTML = errorPanel('Archive unavailable', String(e.message || e));
    });
  }

  function renderPost(slug) {
    setNav('home');
    app.innerHTML = '<div class="status-line">RETRIEVING LOG …</div>';
    fetchJSON('posts/' + encodeURIComponent(slug) + '.json').then(function (p) {
      app.innerHTML = '<div class="blog-posts"><div class="date-outer">' +
        '<h2 class="date-header"><span>' + esc(fmtDate(p.date)) + '</span></h2>' +
        '<div class="post-outer">' +
        '<h3 class="post-title">' + esc(p.title) + '</h3>' +
        '<div class="post-body">' + (p.html || '') + '</div>' +
        '<div class="post-footer">' + tagChips(p.tags) +
        ' <a href="posts/' + encodeURIComponent(p.slug) + '.html">STATIC COPY</a></div>' +
        '</div></div></div>' +
        '<div class="blog-pager"><a href="#/">‹ All logs</a><a href="#/archive">Archive</a></div>';
      animateHeaders(app);
    }).catch(function (e) {
      app.innerHTML = errorPanel('Log not found', String(e.message || e)) +
        '<div class="blog-pager"><a href="#/">‹ All logs</a></div>';
    });
  }

  /* ---------------- private section ---------------- */

  function renderPrivate(postId) {
    setNav('private');
    if (!state.vaultKey) return renderUnlock();
    if (postId) return renderPrivatePost(postId);
    return renderPrivateList();
  }

  function renderUnlock() {
    // Before unlock: ONLY the passphrase prompt. No titles, dates or counts.
    app.innerHTML =
      '<div class="post-outer unlock-panel" id="unlock-panel">' +
      '<h3 class="unlock-title">Restricted archive</h3>' +
      '<p class="unlock-sub">// vault access requires passphrase</p>' +
      '<form id="unlock-form">' +
      '<input class="sf-input" id="unlock-pass" type="password" autocomplete="current-password" ' +
      'placeholder="passphrase" aria-label="Vault passphrase" autofocus>' +
      '<label class="sf-check"><input type="checkbox" id="unlock-remember">' +
      'Remember on this device (this tab only — stores the derived key, never the passphrase)</label>' +
      '<button class="sf-btn" type="submit">Unlock</button>' +
      '<div class="decrypt-progress"><div class="bar" id="decrypt-bar"></div></div>' +
      '<div class="decrypt-status">DECRYPTING…</div>' +
      '<p class="unlock-error" id="unlock-error" role="alert"></p>' +
      '</form></div>';
    animateHeaders(app);

    var panel = $('#unlock-panel');
    var form = $('#unlock-form');
    var passInput = $('#unlock-pass');
    var errorEl = $('#unlock-error');
    var bar = $('#decrypt-bar');

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var pass = passInput.value;
      if (!pass) { errorEl.textContent = 'Enter the vault passphrase.'; return; }
      var remember = $('#unlock-remember').checked;
      errorEl.textContent = '';
      panel.classList.remove('glitch');
      panel.classList.add('decrypting');
      bar.style.width = '4%';

      fetchJSON('private/manifest.json').then(function (manifest) {
        var kdf = {
          id: manifest.kdf,
          salt: manifest.salt,
          m: manifest.params.m, t: manifest.params.t, p: manifest.params.p
        };
        return EzCrypto.deriveVaultKey(pass, kdf, function (done, total) {
          bar.style.width = Math.round(4 + (done / total) * 76) + '%';
        });
      }).then(function (key) {
        bar.style.width = '85%';
        return fetchJSON('private/index.enc').then(function (env) {
          return EzCrypto.decryptEnvelope(env, key).then(function (list) {
            bar.style.width = '100%';
            state.vaultKey = key;
            state.privIndex = list;
            if (remember) {
              try { sessionStorage.setItem(SESSION_KEY, EzCrypto.bytesToB64(key)); } catch (e) {}
            }
            renderPrivateList();
          });
        });
      }).catch(function (e) {
        panel.classList.remove('decrypting');
        passInput.value = '';
        if (e && e.code === 'AUTH_FAILED') {
          // wrong passphrase: glitch-flicker, then a plain readable message
          panel.classList.add('glitch');
          setTimeout(function () { panel.classList.remove('glitch'); }, 1000);
          errorEl.textContent = 'Incorrect passphrase.';
        } else {
          errorEl.textContent = 'Unlock failed: ' + String((e && e.message) || e);
        }
        passInput.focus();
      });
    });
  }

  function renderPrivateList() {
    setNav('private');
    function paint(list) {
      var items = (list || []).slice().sort(function (a, b) {
        return a.date < b.date ? 1 : -1;
      });
      var html = '<div class="blog-posts">';
      html += '<div class="date-outer"><div class="status-line" style="margin-bottom:1em;">' +
        'VAULT UNLOCKED — key held in memory' +
        ' <button class="sf-btn" id="lock-btn" type="button" style="margin-left:1em;">Lock</button>' +
        '</div></div>';
      if (!items.length) {
        html += '<div class="date-outer"><div class="post-outer"><div class="post-body">' +
          'No encrypted posts.</div></div></div>';
      }
      items.forEach(function (p) {
        html += '<div class="date-outer">' +
          '<h2 class="date-header"><span>' + esc(fmtDate(p.date)) + '</span></h2>' +
          '<div class="post-outer">' +
          '<h3 class="post-title"><a href="#/private/' + encodeURIComponent(p.id) + '">' + esc(p.title) + '</a></h3>' +
          '<div class="post-body">' + esc(p.excerpt || '') + '</div>' +
          '<div class="post-footer"><span class="lock-badge">encrypted post</span> ' + tagChips(p.tags) + '</div>' +
          '</div></div>';
      });
      html += '</div>';
      app.innerHTML = html;
      $('#lock-btn').addEventListener('click', function () {
        forgetKey();
        renderUnlock();
      });
      animateHeaders(app);
    }

    if (state.privIndex) return paint(state.privIndex);
    // key remembered but index not decrypted yet (e.g. restored session key)
    app.innerHTML = '<div class="status-line">DECRYPTING INDEX …</div>';
    fetchJSON('private/index.enc').then(function (env) {
      return EzCrypto.decryptEnvelope(env, state.vaultKey);
    }).then(function (list) {
      state.privIndex = list;
      paint(list);
    }).catch(function (e) {
      // stale/invalid remembered key → back to prompt
      forgetKey();
      renderUnlock();
      var errEl = $('#unlock-error');
      if (errEl && e && e.code === 'AUTH_FAILED') {
        errEl.textContent = 'Stored key no longer valid — enter the passphrase.';
      }
    });
  }

  function renderPrivatePost(id) {
    if (!/^[A-Za-z0-9_-]+$/.test(id)) {
      app.innerHTML = errorPanel('Invalid post id', 'The requested id is malformed.');
      return;
    }
    app.innerHTML = '<div class="status-line">DECRYPTING…</div>';
    fetchJSON('private/' + encodeURIComponent(id) + '.enc').then(function (env) {
      return EzCrypto.decryptEnvelope(env, state.vaultKey);
    }).then(function (post) {
      app.innerHTML = '<div class="blog-posts"><div class="date-outer">' +
        '<h2 class="date-header"><span>' + esc(fmtDate(post.date)) + '</span></h2>' +
        '<div class="post-outer">' +
        '<h3 class="post-title">' + esc(post.title) + '</h3>' +
        '<div class="post-body">' + bodyToHtml(post.body) + '</div>' +
        '<div class="post-footer"><span class="lock-badge">encrypted post</span> ' +
        tagChips(post.tags) + '</div>' +
        '</div></div></div>' +
        '<div class="blog-pager"><a href="#/private">‹ Vault index</a></div>';
      animateHeaders(app);
    }).catch(function (e) {
      if (e && e.code === 'AUTH_FAILED') {
        forgetKey();
        renderUnlock();
        var errEl = $('#unlock-error');
        if (errEl) errEl.textContent = 'Incorrect passphrase.';
      } else {
        app.innerHTML = errorPanel('Decryption failed', String((e && e.message) || e)) +
          '<div class="blog-pager"><a href="#/private">‹ Vault index</a></div>';
      }
    });
  }

  /* ---------------- sidebar ---------------- */

  function renderArchiveWidget(ix) {
    var ul = $('#archive-widget');
    if (!ul) return;
    var posts = (ix.posts || ix).slice().sort(function (a, b) {
      return a.date < b.date ? 1 : -1;
    });
    var counts = {}, order = [];
    posts.forEach(function (p) {
      var k = monthKey(p.date);
      if (!(k in counts)) { counts[k] = 0; order.push(k); }
      counts[k]++;
    });
    ul.innerHTML = order.map(function (k) {
      return '<li><a href="#/archive">' + esc(monthLabel(k)) + '</a> (' + counts[k] + ')</li>';
    }).join('');
  }

  function installSearch() {
    var input = $('#search-input');
    if (!input) return;
    input.addEventListener('input', function () {
      state.search = input.value;
      if (currentRoute() === 'home') renderHome();
      else location.hash = '#/';
    });
  }

  /* ---------------- router ---------------- */

  function currentRoute() {
    var h = location.hash;
    if (h.indexOf('#/post/') === 0) return 'post';
    if (h.indexOf('#/private') === 0) return 'private';
    if (h === '#/archive') return 'archive';
    return 'home';
  }

  function route() {
    var h = location.hash;
    if (h.indexOf('#/post/') === 0) {
      renderPost(decodeURIComponent(h.slice(7)));
    } else if (h.indexOf('#/private/') === 0) {
      renderPrivate(decodeURIComponent(h.slice(10)));
    } else if (h === '#/private') {
      renderPrivate(null);
    } else if (h === '#/archive') {
      renderArchive();
    } else {
      renderHome();
    }
  }

  /* ================================================================
   * Boot
   * ================================================================ */

  function boot() {
    installSoundToggle();
    if (!app) {
      // pre-rendered post page: chrome only, text is already in the HTML
      animateHeaders(document);
      return;
    }
    restoreRememberedKey();
    installSearch();
    window.addEventListener('hashchange', route);
    loadIndex().catch(function () { /* home view reports the error */ });
    route();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
