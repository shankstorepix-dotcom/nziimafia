/* NZI — Cursor "blood".
   Gota de sangue como ponteiro (a ponta é o ponto de clique) + anel suave + respingos ao clicar.
   Princípios:
   - Só liga com mouse/caneta (hover + pointer fino). Em telas de toque nada muda.
   - Desliga com "forced-colors" (alto contraste) e com data-nz-cursor="off" no <html>.
   - prefers-reduced-motion: ponteiro fixo, sem anel com atraso, sem rastro e sem respingos.
   - Campos de texto mantêm o cursor "I" nativo; iframes (Spotify) usam o cursor deles.
   - Elementos do cursor têm pointer-events:none e aria-hidden: cliques, seleção de texto e foco não são afetados.
   - Sem rastreio de dados, sem dependências. O canvas só redesenha enquanto há partículas. */
(function () {
  'use strict';
  if (window.__nzBloodCursor) return;
  window.__nzBloodCursor = true;

  var de = document.documentElement;
  if (!window.matchMedia || de.getAttribute('data-nz-cursor') === 'off') return;
  if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;
  if (window.matchMedia('(forced-colors: active)').matches) return;
  // O CSS abaixo usa :is(); sem suporte, mantém o cursor nativo em vez de arriscar ficar sem cursor.
  if (!(window.CSS && CSS.supports && CSS.supports('selector(:is(a))'))) return;

  var reduceMq = window.matchMedia('(prefers-reduced-motion: reduce)');
  var reduce = reduceMq.matches;
  var onReduce = function (e) { reduce = e.matches; };
  if (reduceMq.addEventListener) reduceMq.addEventListener('change', onReduce);
  else if (reduceMq.addListener) reduceMq.addListener(onReduce);

  var TEXT_SEL = 'input:not([type=range]):not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]):not([type=reset]):not([type=color]):not([type=file]),textarea,[contenteditable=""],[contenteditable="true"]';
  var HOVER_SEL = 'a[href],button,summary,select,label,input[type=range],input[type=checkbox],input[type=radio],input[type=submit],input[type=button],[role=button],[role=tab],[data-cursor="hover"]';
  var COLORS = ['255,42,58', '214,22,36', '170,14,26', '120,9,18'];

  var CSS_TEXT =
    'html.nz-bc-on,html.nz-bc-on *{cursor:none!important}' +
    'html.nz-bc-on :is(' + TEXT_SEL + '){cursor:text!important}' +
    '.nz-bc{position:fixed;left:0;top:0;width:100%;height:100%;pointer-events:none;z-index:2147483647;overflow:hidden;opacity:1;transition:opacity .15s}' +
    '.nz-bc.is-hidden{opacity:0}' +
    '.nz-bc canvas{position:absolute;left:0;top:0;width:100%;height:100%;pointer-events:none}' +
    '.nz-bc-ring{position:absolute;left:0;top:0;width:30px;height:30px;margin:-15px 0 0 -15px;border-radius:50%;' +
    'border:1px solid rgba(255,42,58,.5);background:rgba(255,42,58,0);box-shadow:0 0 10px rgba(255,42,58,.16),inset 0 0 8px rgba(110,13,22,.35);' +
    'will-change:transform;transition:width .2s,height .2s,margin .2s,border-color .2s,background-color .2s}' +
    '.nz-bc.is-link .nz-bc-ring{width:44px;height:44px;margin:-22px 0 0 -22px;border-color:rgba(255,42,58,.9);background:rgba(255,42,58,.08)}' +
    '.nz-bc.is-down .nz-bc-ring{width:20px;height:20px;margin:-10px 0 0 -10px;border-color:#ff2a3a}' +
    '.nz-bc-drop{position:absolute;left:0;top:0;width:0;height:0;will-change:transform}' +
    '.nz-bc-drop svg{position:absolute;left:-7px;top:0;width:14px;height:19px;overflow:visible;transform-origin:50% 0;transform:rotate(-38deg);' +
    'filter:drop-shadow(0 0 5px rgba(255,42,58,.5));transition:transform .12s}' +
    '.nz-bc.is-link .nz-bc-drop svg{transform:rotate(-38deg) scale(1.12)}' +
    '.nz-bc.is-down .nz-bc-drop svg{transform:rotate(-38deg) scale(.8)}' +
    '@media (prefers-reduced-motion:reduce){.nz-bc-ring,.nz-bc-drop svg,.nz-bc{transition:none!important}}';

  var DROP_SVG =
    '<svg viewBox="0 0 16 21" aria-hidden="true" focusable="false">' +
    '<defs><linearGradient id="nzBcG" x1="0" y1="0" x2="1" y2="1">' +
    '<stop offset="0" stop-color="#ff4a58"/><stop offset=".55" stop-color="#d4161f"/><stop offset="1" stop-color="#6e0d16"/></linearGradient></defs>' +
    '<path d="M8 0C8 0 1 8.2 1 13.2a7 7 0 0 0 14 0C15 8.2 8 0 8 0Z" fill="url(#nzBcG)"/>' +
    '<ellipse cx="5.4" cy="13" rx="1.3" ry="2.6" fill="#fff" opacity=".28" transform="rotate(14 5.4 13)"/></svg>';

  var root, dropEl, ringEl, canvas, ctx;
  var built = false, active = false;
  var mx = -100, my = -100, rx = -100, ry = -100;
  var isDown = false, isLink = false, isText = false, isFrame = false;
  var parts = [], raf = 0, lastT = 0, lastTrail = 0, lastTx = 0, lastTy = 0, dirty = false;
  var W = 0, H = 0, dpr = 1, resizeT = 0;

  function build() {
    if (built) return;
    built = true;
    var st = document.createElement('style');
    st.setAttribute('data-nz-bc', '');
    st.textContent = CSS_TEXT;
    document.head.appendChild(st);

    root = document.createElement('div');
    root.className = 'nz-bc is-hidden';
    root.setAttribute('aria-hidden', 'true');
    canvas = document.createElement('canvas');
    ringEl = document.createElement('div'); ringEl.className = 'nz-bc-ring';
    dropEl = document.createElement('div'); dropEl.className = 'nz-bc-drop'; dropEl.innerHTML = DROP_SVG;
    root.appendChild(canvas); root.appendChild(ringEl); root.appendChild(dropEl);
    document.body.appendChild(root);
    ctx = canvas.getContext('2d');
    sizeCanvas();
  }

  function sizeCanvas() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function activate() {
    if (active) return;
    build();
    active = true;
    de.classList.add('nz-bc-on');
    syncVisibility();
  }
  function deactivate() {
    if (!active) return;
    active = false;
    de.classList.remove('nz-bc-on');
    isDown = false;
    root.classList.add('is-hidden');
    root.classList.remove('is-down');
  }
  function syncVisibility() {
    if (!built) return;
    var hide = !active || isText || isFrame;
    root.classList.toggle('is-hidden', hide);
    root.classList.toggle('is-link', isLink && !hide);
    root.classList.toggle('is-down', isDown && !hide);
  }

  function place() {
    dropEl.style.transform = 'translate3d(' + mx + 'px,' + my + 'px,0)';
  }

  /* ---------- partículas ---------- */
  function rand(a, b) { return a + Math.random() * (b - a); }
  function add(p) { if (parts.length > 140) parts.shift(); parts.push(p); }

  function splash(x, y) {
    if (reduce) return;
    // onda de choque
    add({ k: 'ring', x: x, y: y, age: 0, life: 380 });
    // mancha que some devagar
    add({ k: 'stain', x: x, y: y, age: 0, life: 900, r: rand(5, 8), s: Math.random() * 6 });
    // gotículas
    var n = 12, i, a, sp;
    for (i = 0; i < n; i++) {
      a = (Math.PI * 2 * i) / n + rand(-0.3, 0.3);
      sp = rand(90, 270);
      add({ k: 'drop', x: x, y: y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp - 70, r: rand(1.3, 3.2), age: 0, life: rand(520, 900), c: COLORS[(Math.random() * COLORS.length) | 0] });
    }
    // 2 gotas grandes e lentas
    for (i = 0; i < 2; i++) {
      a = rand(0, Math.PI * 2);
      add({ k: 'drop', x: x, y: y, vx: Math.cos(a) * rand(30, 70), vy: Math.sin(a) * rand(30, 70) - 40, r: rand(3.4, 4.6), age: 0, life: rand(700, 1000), c: COLORS[1] });
    }
    kick();
  }

  function trail(x, y) {
    if (reduce || isDown) return;
    add({ k: 'drop', x: x, y: y + 6, vx: rand(-10, 10), vy: rand(8, 30), r: rand(1.1, 2.1), age: 0, life: rand(450, 750), c: COLORS[(Math.random() * COLORS.length) | 0] });
    kick();
  }

  function draw(dt) {
    ctx.clearRect(0, 0, W, H);
    var g = 820, drag = Math.pow(0.9, dt / 16.7), i, p, t, a, sp, ang;
    for (i = parts.length - 1; i >= 0; i--) {
      p = parts[i];
      p.age += dt;
      t = p.age / p.life;
      if (t >= 1) { parts.splice(i, 1); continue; }
      if (p.k === 'ring') {
        a = (1 - t) * 0.65;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 6 + 30 * (1 - Math.pow(1 - t, 3)), 0, 6.2832);
        ctx.lineWidth = 1.6 * (1 - t) + 0.3;
        ctx.strokeStyle = 'rgba(255,42,58,' + a.toFixed(3) + ')';
        ctx.stroke();
      } else if (p.k === 'stain') {
        a = (1 - t) * 0.34;
        ctx.fillStyle = 'rgba(150,12,24,' + a.toFixed(3) + ')';
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * (0.7 + 0.5 * t), 0, 6.2832);
        ctx.arc(p.x + Math.cos(p.s) * 4, p.y + Math.sin(p.s) * 4, p.r * 0.55, 0, 6.2832);
        ctx.arc(p.x + Math.cos(p.s + 2.4) * 5, p.y + Math.sin(p.s + 2.4) * 5, p.r * 0.4, 0, 6.2832);
        ctx.fill();
      } else {
        p.vy += g * dt / 1000;
        p.vx *= drag; p.vy *= (0.5 + 0.5 * drag);
        p.x += p.vx * dt / 1000; p.y += p.vy * dt / 1000;
        a = Math.pow(1 - t, 1.3);
        sp = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
        ang = Math.atan2(p.vy, p.vx);
        ctx.fillStyle = 'rgba(' + p.c + ',' + a.toFixed(3) + ')';
        ctx.beginPath();
        ctx.ellipse(p.x, p.y, p.r * (1 + Math.min(sp, 400) * 0.0035), p.r, ang, 0, 6.2832);
        ctx.fill();
      }
    }
    dirty = parts.length > 0;
    if (!dirty) ctx.clearRect(0, 0, W, H);
  }

  /* ---------- laço de animação: só roda quando há o que animar ---------- */
  function kick() { if (!raf) { lastT = 0; raf = requestAnimationFrame(frame); } }
  function frame(t) {
    raf = 0;
    var dt = lastT ? Math.min(t - lastT, 34) : 16;
    lastT = t;
    var busy = false;
    var k = reduce ? 1 : 1 - Math.pow(0.001, dt / 1000 * 1.0); // ~suavização independente de FPS
    rx += (mx - rx) * k; ry += (my - ry) * k;
    if (Math.abs(mx - rx) > 0.15 || Math.abs(my - ry) > 0.15) busy = true; else { rx = mx; ry = my; }
    ringEl.style.transform = 'translate3d(' + rx.toFixed(1) + 'px,' + ry.toFixed(1) + 'px,0)';
    if (parts.length || dirty) { draw(dt); busy = busy || parts.length > 0; }
    if (busy) raf = requestAnimationFrame(frame);
  }

  /* ---------- eventos ---------- */
  function classify(target) {
    var el = target && target.nodeType === 1 ? target : (target && target.parentElement);
    if (!el || !el.closest) { isLink = isText = isFrame = false; return; }
    isFrame = el.tagName === 'IFRAME';
    isText = !!el.closest(TEXT_SEL);
    var h = el.closest(HOVER_SEL);
    isLink = !!h && !h.disabled && h.getAttribute('aria-disabled') !== 'true';
  }

  document.addEventListener('pointermove', function (e) {
    if (e.pointerType === 'touch') { deactivate(); return; }
    var first = !active;
    if (first) { activate(); classify(e.target); }
    mx = e.clientX; my = e.clientY;
    if (first) { rx = mx; ry = my; }
    place();
    syncVisibility();
    if (!reduce) {
      var now = e.timeStamp || performance.now();
      var dx = mx - lastTx, dy = my - lastTy;
      if (dx * dx + dy * dy > 196 && now - lastTrail > 70) { lastTrail = now; lastTx = mx; lastTy = my; trail(mx, my); }
    }
    kick();
  }, { passive: true });

  document.addEventListener('pointerover', function (e) {
    if (e.pointerType === 'touch') return;
    classify(e.target);
    syncVisibility();
  }, { passive: true });

  document.addEventListener('pointerdown', function (e) {
    if (e.pointerType === 'touch') { deactivate(); return; }
    if (!active || e.button !== 0) return;
    isDown = true; syncVisibility();
    if (!isText && !isFrame) splash(e.clientX, e.clientY);
  }, { passive: true });

  function up() { if (!isDown) return; isDown = false; syncVisibility(); }
  document.addEventListener('pointerup', up, { passive: true });
  document.addEventListener('pointercancel', up, { passive: true });
  window.addEventListener('blur', function () { up(); if (built) root.classList.add('is-hidden'); });
  document.addEventListener('visibilitychange', function () { if (document.hidden) { up(); if (built) root.classList.add('is-hidden'); } });
  document.addEventListener('mouseout', function (e) { if (!e.relatedTarget && built) root.classList.add('is-hidden'); });
  document.addEventListener('mouseover', function () { if (active) syncVisibility(); });
  window.addEventListener('resize', function () {
    if (!built) return;
    clearTimeout(resizeT); resizeT = setTimeout(sizeCanvas, 120);
  });
})();
