/* NZI — Acessos por estado (página inicial do dashboard, somente administradores).
   Só exibe dados vindos do back-end (/api/tracking/home). Não existe dado de demonstração:
   sem acessos reais o painel mostra zero. Atualiza sozinho: SSE (instantâneo) + consulta a cada 15 s. */
(function () {
  'use strict';

  var POLL_MS = 15000;
  var NS = 'http://www.w3.org/2000/svg';
  var TILES = { // mapa em grade (reserva, caso o pacote @svg-maps/brazil não esteja instalado)
    RR: [3, 0], AP: [5, 0],
    AM: [2, 1], PA: [4, 1], MA: [5, 1], CE: [6, 1], RN: [7, 1],
    AC: [1, 2], RO: [2, 2], MT: [3, 2], TO: [4, 2], PI: [5, 2], PE: [6, 2], PB: [7, 2],
    MS: [3, 3], GO: [4, 3], BA: [5, 3], AL: [6, 3], SE: [7, 3],
    PR: [3, 4], DF: [4, 4], MG: [5, 4], ES: [6, 4],
    SC: [3, 5], SP: [4, 5], RJ: [5, 5], RS: [3, 6]
  };

  var S = {
    built: false, running: false, data: null, shape: null, shapeTried: false,
    mapBuilt: false, selected: null, hovered: null, es: null, live: false,
    poll: null, debounce: null, busy: false, again: false, seen: null, paths: {}
  };
  var root;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function $(sel) { return root.querySelector(sel); }
  function fmt(n) { return Number(n || 0).toLocaleString('pt-BR'); }
  function pct(n) { return Number(n || 0).toLocaleString('pt-BR', { maximumFractionDigits: 1 }) + '%'; }
  function fmtDate(iso) {
    try { return new Date(iso).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'short', timeStyle: 'medium' }); }
    catch (e) { return iso; }
  }
  var regionNames = null;
  function countryName(code) {
    if (!code) return '—';
    try { regionNames = regionNames || new Intl.DisplayNames(['pt-BR'], { type: 'region' }); return regionNames.of(code) || code; }
    catch (e) { return code; }
  }

  /* Intensidade: cinza-escuro sem acessos; com acessos, vermelho que cresce (escala log, nunca "apagado"). */
  var ZERO = '#27272b';
  function colorFor(v, max) {
    if (!v) return ZERO;
    var t = max <= 1 ? 1 : 0.2 + 0.8 * (Math.log(1 + v) / Math.log(1 + max));
    var r = Math.round(92 + (255 - 92) * t), g = Math.round(11 + (26 - 11) * t), b = Math.round(20 + (46 - 20) * t);
    return 'rgb(' + r + ',' + g + ',' + b + ')';
  }
  function stateInfo(uf) {
    var l = S.data ? S.data.states : [];
    for (var i = 0; i < l.length; i++) if (l[i].uf === uf) return l[i];
    return null;
  }
  function maxVisits() { return S.data.states.reduce(function (m, s) { return Math.max(m, s.visits); }, 0); }

  /* ------------------------------------------------------------ estrutura */
  function stat(icon, label, id) {
    return '<div class="card stat"><div class="ring"><svg><use href="#' + icon + '"/></svg></div><div>' +
      '<div class="label">' + label + '</div><div class="value accent" id="' + id + '">0</div><div class="sub" id="' + id + 'S"></div></div></div>';
  }
  function build() {
    root = document.getElementById('trkRoot');
    if (!root) return false;
    root.innerHTML =
      '<div class="trk-head"><div><h2>Acessos <span>por estado</span></h2>' +
      '<p>Visitantes do site da NZI, localizados por IP (aproximado) e somados no banco de dados.</p></div>' +
      '<div class="trk-status" id="trkStatus" role="status" aria-live="polite"><span class="trk-dot"></span><span id="trkStatusTxt">Conectando…</span><span class="trk-online" id="trkOnline" hidden></span></div></div>' +
      '<div class="trk-notice" id="trkNotice" hidden></div>' +
      '<div class="trk-kpis">' +
      stat('i-chart', 'Total de acessos', 'kVisits') +
      stat('i-globe', 'Estados alcançados', 'kStates') +
      stat('i-target', 'Estado com mais visitas', 'kTop') +
      '</div>' +
      '<div class="trk-main">' +
      '<div class="card trk-mapcard"><div class="trk-map" id="trkMap"><p class="trk-empty">Carregando mapa…</p></div>' +
      '<div class="trk-legend"><span><i class="sw zero"></i>Sem acessos</span><span class="ramp" aria-hidden="true"></span><span>Mais acessos</span><span class="trk-credit" id="trkCredit"></span></div></div>' +
      '<aside class="card trk-side"><div class="trk-detail" id="trkDetail" aria-live="polite"></div>' +
      '<h3>Estados com mais acessos</h3><ol class="trk-rank" id="trkRank"></ol></aside>' +
      '</div>' +
      '<div class="card trk-recent"><div class="card-title"><span class="l"><svg><use href="#i-log"/></svg>Acessos recentes</span><span class="badge badge-in" id="trkRecentN"></span></div>' +
      '<div class="table-wrap"><table class="data-table trk-table"><thead><tr><th>Data e hora</th><th>Estado</th><th>Cidade (aprox.)</th><th>País</th><th>IP (truncado)</th><th>Página</th></tr></thead>' +
      '<tbody id="trkBody"><tr><td colspan="6" class="trk-empty">Carregando…</td></tr></tbody></table></div></div>' +
      '<p class="trk-foot" id="trkFoot"></p>';
    renderDetail();
    S.built = true;
    return true;
  }

  /* ------------------------------------------------------------ dados */
  function api(path) {
    return fetch(path, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } }).then(function (r) {
      return r.json().catch(function () { return { success: false, error: 'Resposta inválida do servidor.' }; })
        .then(function (j) { j._status = r.status; return j; });
    });
  }
  function load() {
    if (!S.running) return Promise.resolve();
    if (S.busy) { S.again = true; return Promise.resolve(); }
    S.busy = true;
    var shapeReq = (S.shape || S.shapeTried) ? Promise.resolve(null) : api('/api/tracking/map-shape');
    return Promise.all([api('/api/tracking/home?limit=15'), shapeReq]).then(function (res) {
      var d = res[0], sh = res[1];
      if (sh) { S.shapeTried = true; if (sh.success) S.shape = sh; }
      if (!d.success) { showError(d); return; }
      S.data = d;
      render();
    }).catch(function () {
      showError({ error: 'Falha de conexão com o servidor. Tentando de novo em instantes.' });
    }).then(function () {
      S.busy = false;
      if (S.again) { S.again = false; load(); }
    });
  }
  function schedule() { // vários eventos seguidos viram uma única consulta
    clearTimeout(S.debounce);
    S.debounce = setTimeout(load, 250);
  }
  function showError(d) {
    var n = $('#trkNotice');
    n.hidden = false;
    n.innerHTML = '<b>Não foi possível atualizar os acessos.</b> ' + esc(d.error || 'Erro desconhecido.') +
      (d._status === 401 || d._status === 403 ? ' Este painel é exclusivo para administradores (Dono e Fundador).' : '');
    setStatus(false);
    if (d._status === 401 || d._status === 403) stop();
  }

  /* ------------------------------------------------------------ tempo real */
  function setStatus(live) {
    S.live = live;
    var el = $('#trkStatus');
    if (!el) return;
    el.classList.toggle('on', live);
    $('#trkStatusTxt').textContent = live ? 'Ao vivo' : 'Atualizando a cada ' + (POLL_MS / 1000) + ' s';
  }
  function connectStream() {
    if (S.es || !window.EventSource) return;
    var es = new EventSource('/api/tracking/stream');
    S.es = es;
    es.onopen = function () { setStatus(true); schedule(); };
    es.addEventListener('visit', schedule);
    es.onerror = function () {
      setStatus(false);
      if (es.readyState === 2) { S.es = null; } // fechado (ex.: sessão expirada): a consulta periódica mostra o motivo
    };
  }
  function disconnectStream() {
    if (S.es) { S.es.close(); S.es = null; }
  }
  function onVisibility() { if (document.visibilityState === 'visible' && S.running) { load(); if (!S.es) connectStream(); } }

  /* ------------------------------------------------------------ render */
  function render() {
    var d = S.data, t = d.totals, o = d.outside, c = d.config;
    $('#kVisits').textContent = fmt(t.visits);
    $('#kVisitsS').textContent = 'desde o início do registro';
    $('#kStates').textContent = fmt(t.statesReached) + ' / 27';
    $('#kStatesS').textContent = t.statesReached ? 'estados com pelo menos 1 acesso' : 'nenhum estado alcançado ainda';
    $('#kTop').textContent = t.topState ? t.topState.uf : '—';
    $('#kTopS').textContent = t.topState ? t.topState.name + ' · ' + fmt(t.topState.visits) + ' acessos' : 'aguardando o primeiro acesso';
    var on = $('#trkOnline');
    on.hidden = false;
    on.textContent = fmt(t.onlineNow) + ' online agora';
    setStatus(S.live);

    renderNotice(d);
    renderMap();
    renderDetail();
    renderRank();
    renderRecent();
    $('#trkFoot').innerHTML = 'Localização aproximada por IP (' + esc(c.geoProvider) + '); não identifica pessoas nem endereços. ' +
      'O IP é guardado ' + (c.storesFullIp ? '<b>completo</b> (opção ativada no servidor)' : 'truncado') + ' por ' + fmt(c.retentionDays) + ' dias e depois apagado; ' +
      'os totais por estado são apenas contadores, sem dados pessoais, e ficam acumulados. ' +
      'Sem cookies; respeita Do Not Track. Armazenamento: ' + ({ supabase: 'Supabase', local: 'arquivo local (data/visits.json)' }[c.storage] || esc(c.storage)) + '.';
  }

  function renderNotice(d) {
    var o = d.outside, c = d.config, msgs = [];
    if (c.geoMode === 'off') msgs.push('<b>Localização desativada</b> (<code>GEO_PROVIDER=off</code>). Os acessos são contados, mas sem estado nem cidade.');
    if (!d.totals.statesReached && o.local > 0 && d.totals.visits === o.local) {
      msgs.push('Todos os acessos vieram da rede local (ex.: localhost), que não tem localização. Se o site já está online atrás de proxy/CDN (Render, Railway, Nginx, Cloudflare), defina <code>TRUST_PROXY=1</code> no <code>.env</code> para registrar o IP real do visitante.');
    }
    var out = [];
    if (o.foreign) out.push(fmt(o.foreign) + ' do exterior');
    if (o.unknown) out.push(fmt(o.unknown) + ' sem localização');
    if (o.local && !(d.totals.visits === o.local)) out.push(fmt(o.local) + ' da rede local');
    if (out.length) msgs.push('Fora do mapa: ' + out.join(' · ') + '. Esses acessos entram no total, mas não pintam nenhum estado.');
    var n = $('#trkNotice');
    n.hidden = !msgs.length;
    n.innerHTML = msgs.map(function (m) { return '<div>' + m + '</div>'; }).join('');
  }

  /* ---- mapa ---- */
  function svgEl(name, attrs) {
    var e = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }
  function bindState(el, uf) {
    el.setAttribute('class', 'uf');
    el.setAttribute('tabindex', '0'); el.setAttribute('role', 'button');
    el.setAttribute('data-uf', uf);
    el.addEventListener('click', function () { select(uf); });
    el.addEventListener('mouseenter', function () { S.hovered = uf; renderDetail(); });
    el.addEventListener('mouseleave', function () { S.hovered = null; renderDetail(); });
    el.addEventListener('focus', function () { S.hovered = uf; renderDetail(); });
    el.addEventListener('blur', function () { S.hovered = null; renderDetail(); });
    el.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(uf); } });
    S.paths[uf] = el;
  }
  function buildMap() {
    var host = $('#trkMap');
    if (!host.getBoundingClientRect().width) return; // seção oculta: tenta de novo no próximo ciclo
    var shape = S.shape && !S.shape.fallback ? S.shape : null;
    host.innerHTML = '';
    S.paths = {};
    var svg = svgEl('svg', { role: 'group', 'aria-label': 'Mapa do Brasil dividido por estados, colorido pela quantidade de acessos' });
    if (shape) {
      svg.setAttribute('viewBox', shape.viewBox);
      shape.locations.forEach(function (l) { var p = svgEl('path', { d: l.path }); bindState(p, l.uf); svg.appendChild(p); });
      $('#trkCredit').textContent = shape.attribution || '';
    } else {
      var Z = 62, G = 5, cols = 8, rows = 7;
      svg.setAttribute('viewBox', '0 0 ' + (cols * (Z + G)) + ' ' + (rows * (Z + G)));
      Object.keys(TILES).forEach(function (uf) {
        var r = svgEl('rect', { x: TILES[uf][0] * (Z + G), y: TILES[uf][1] * (Z + G), width: Z, height: Z, rx: 9 });
        bindState(r, uf); svg.appendChild(r);
        var tx = svgEl('text', { x: TILES[uf][0] * (Z + G) + Z / 2, y: TILES[uf][1] * (Z + G) + Z / 2 });
        tx.textContent = uf; svg.appendChild(tx);
      });
      $('#trkCredit').textContent = 'Mapa em grade (instale @svg-maps/brazil para os contornos reais)';
    }
    host.appendChild(svg);
    if (shape) Object.keys(S.paths).forEach(function (uf) { // sigla no centro de cada estado
      try {
        var bb = S.paths[uf].getBBox();
        if (bb.width > 22 && bb.height > 16) {
          var tx = svgEl('text', { x: bb.x + bb.width / 2, y: bb.y + bb.height / 2 });
          tx.textContent = uf; svg.appendChild(tx);
        }
      } catch (e) { /* ignora */ }
    });
    S.mapBuilt = true;
  }
  function renderMap() {
    if (!S.mapBuilt) buildMap();
    if (!S.mapBuilt) return;
    var max = maxVisits();
    Object.keys(S.paths).forEach(function (uf) {
      var el = S.paths[uf], s = stateInfo(uf), v = s ? s.visits : 0;
      el.style.fill = colorFor(v, max);
      el.setAttribute('aria-label', (s ? s.name : uf) + ': ' + fmt(v) + ' acessos');
      el.classList.toggle('sel', S.selected === uf);
      var tt = el.querySelector('title');
      if (!tt) { tt = document.createElementNS(NS, 'title'); el.appendChild(tt); }
      tt.textContent = (s ? s.name : uf) + ' — ' + fmt(v) + (v === 1 ? ' acesso' : ' acessos') + ' (' + pct(s ? s.percent : 0) + ')';
      if (S.prev && S.prev[uf] != null && v > S.prev[uf]) { // acesso novo neste estado: pulso curto
        el.classList.remove('pulse'); void el.getBoundingClientRect(); el.classList.add('pulse');
      }
    });
    S.prev = {};
    S.data.states.forEach(function (s) { S.prev[s.uf] = s.visits; });
  }
  S.prev = null;

  function select(uf) {
    S.selected = S.selected === uf ? null : uf;
    Object.keys(S.paths).forEach(function (k) { S.paths[k].classList.toggle('sel', S.selected === k); });
    renderDetail();
  }
  function renderDetail() {
    var d = $('#trkDetail');
    if (!d) return;
    var uf = S.hovered || S.selected, s = uf && S.data ? stateInfo(uf) : null;
    if (!s) {
      d.innerHTML = '<p class="hint">Passe o mouse ou toque em um estado para ver o total de acessos, a participação e a posição no ranking.</p>';
      return;
    }
    d.innerHTML = '<div class="name">' + esc(s.name) + '<span>' + esc(s.uf) + '</span></div>' +
      '<div class="row"><span>Acessos</span><b>' + fmt(s.visits) + '</b></div>' +
      '<div class="row"><span>Participação no total</span><b>' + pct(s.percent) + '</b></div>' +
      '<div class="row"><span>Posição</span><b>' + (s.rank ? s.rank + 'º de 27' : 'sem acessos') + '</b></div>';
  }
  function renderRank() {
    var ol = $('#trkRank'), list = S.data.states.filter(function (s) { return s.visits > 0; }).slice(0, 8);
    if (!list.length) { ol.innerHTML = '<li class="trk-empty">Nenhum acesso localizado em estados brasileiros ainda.</li>'; return; }
    var max = list[0].visits;
    ol.innerHTML = list.map(function (s) {
      return '<li data-uf="' + esc(s.uf) + '"><span class="pos">' + s.rank + 'º</span>' +
        '<span class="bar"><i style="width:' + Math.max(6, (s.visits / max) * 100) + '%"></i><span class="nm">' + esc(s.name) + '</span></span>' +
        '<span class="n">' + fmt(s.visits) + '</span></li>';
    }).join('');
    Array.prototype.forEach.call(ol.querySelectorAll('li[data-uf]'), function (li) {
      li.addEventListener('click', function () { select(li.getAttribute('data-uf')); });
    });
  }

  /* ---- tabela ---- */
  function renderRecent() {
    var rows = S.data.recent, tb = $('#trkBody'), fresh = S.seen;
    $('#trkRecentN').textContent = rows.length ? 'últimos ' + rows.length : 'sem registros';
    if (!rows.length) {
      tb.innerHTML = '<tr><td colspan="6" class="trk-empty">Nenhum acesso registrado ainda. Eles aparecem aqui assim que alguém abrir o site público.</td></tr>';
      S.seen = {};
      return;
    }
    var seen = {};
    tb.innerHTML = rows.map(function (r) {
      seen[r.id] = 1;
      var isNew = fresh && !fresh[r.id];
      var loc = r.geoSource === 'local' ? '<span class="trk-tag dim">rede local</span>'
        : (r.stateName ? esc(r.stateName) + ' <span class="trk-tag">' + esc(r.state) + '</span>' : '<span class="trk-tag dim">não localizado</span>');
      return '<tr' + (isNew ? ' class="new"' : '') + '><td>' + esc(fmtDate(r.ts)) + '</td><td>' + loc + '</td><td>' + (r.city ? esc(r.city) : '—') +
        '</td><td>' + esc(countryName(r.country)) + '</td><td><code>' + esc(r.ip) + '</code></td><td>' + esc(r.page) + '</td></tr>';
    }).join('');
    S.seen = seen;
  }

  /* ------------------------------------------------------------ ciclo de vida */
  function start() {
    if (S.running) return;
    if (!S.built && !build()) return;
    S.running = true;
    setStatus(false);
    load();
    connectStream();
    S.poll = setInterval(function () { if (document.visibilityState === 'visible') load(); }, POLL_MS);
    document.addEventListener('visibilitychange', onVisibility);
  }
  function stop() {
    S.running = false;
    clearInterval(S.poll); S.poll = null;
    clearTimeout(S.debounce);
    disconnectStream();
    document.removeEventListener('visibilitychange', onVisibility);
  }

  window.NZITracking = { start: start, stop: stop };
})();
