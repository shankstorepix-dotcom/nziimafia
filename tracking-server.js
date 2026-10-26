'use strict';
/**
 * NZI — Rastreamento de acessos (localização APROXIMADA por IP, acumulada por estado)
 *
 * Como funciona
 *  1. O site público (index.html) envia um beacon para POST /api/track.
 *  2. O servidor lê o IP real, consulta uma API de geolocalização (IPinfo com token, ou ipwho.is sem chave)
 *     e descobre país / estado / cidade aproximada.
 *  3. Grava (a) um registro individual com IP TRUNCADO e (b) incrementa contadores acumulados por estado.
 *  4. O dashboard (somente administradores) lê tudo por GET /api/tracking/home e recebe um aviso em tempo
 *     real por SSE (GET /api/tracking/stream) sempre que entra um acesso novo.
 *
 * Privacidade (LGPD — minimização, finalidade, transparência)
 *  - O IP completo existe só em memória durante a consulta. Fica gravado o IP truncado (a.b.c.xxx / IPv6 /48)
 *    e um hash HMAC não reversível do visitante.
 *  - Sem cookies; o User-Agent não é guardado inteiro (apenas "Navegador (desktop/móvel)").
 *  - Respeita Do Not Track (DNT) e Global Privacy Control (Sec-GPC).
 *  - Registros individuais expiram (TRACKING_RETENTION_DAYS, padrão 90). Os contadores por estado são só
 *    números agregados (sem IP) e por isso permanecem.
 *  - Tokens de API ficam só no servidor. Consulta e stream exigem sessão de administrador (Dono/Fundador).
 *  - Nada de dados fictícios: sem acessos reais, o painel mostra zero.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const https = require('https');
const express = require('express');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
const VISITS_FILE = path.join(DATA_DIR, 'visits.json');

function envInt(name, def, min, max) {
  const n = parseInt(process.env[name], 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}
const cfg = {
  retentionDays: envInt('TRACKING_RETENTION_DAYS', 90, 7, 365),
  storeFullIp: String(process.env.TRACKING_STORE_FULL_IP || '').toLowerCase() === 'true',
  ipinfoToken: () => (process.env.IPINFO_TOKEN || '').trim(),
  // auto (padrão) | ipinfo | ipwhois | off   — "off" nunca envia IP a terceiros (sem localização)
  geoMode: () => String(process.env.GEO_PROVIDER || 'auto').trim().toLowerCase(),
  hashSecret: () => process.env.TRACKING_HASH_SECRET || process.env.JWT_SECRET || 'nzi-tracking-secret',
  onlineWindowMs: 2 * 60 * 1000
};

const UFS = {
  AC: 'Acre', AL: 'Alagoas', AP: 'Amapá', AM: 'Amazonas', BA: 'Bahia', CE: 'Ceará',
  DF: 'Distrito Federal', ES: 'Espírito Santo', GO: 'Goiás', MA: 'Maranhão',
  MT: 'Mato Grosso', MS: 'Mato Grosso do Sul', MG: 'Minas Gerais', PA: 'Pará',
  PB: 'Paraíba', PR: 'Paraná', PE: 'Pernambuco', PI: 'Piauí', RJ: 'Rio de Janeiro',
  RN: 'Rio Grande do Norte', RS: 'Rio Grande do Sul', RO: 'Rondônia', RR: 'Roraima',
  SC: 'Santa Catarina', SP: 'São Paulo', SE: 'Sergipe', TO: 'Tocantins'
};
const PAGES = {
  inicio: { path: '/', label: 'Início' },
  entretenimento: { path: '/#entretenimento', label: 'Entretenimento' },
  recrutamento: { path: '/#recrutamento', label: 'Recrutamento' },
  login: { path: '/#login', label: 'Login' }
};
// Chaves especiais dos contadores (além das 27 UFs)
const K_ALL = '_ALL', K_FOREIGN = '_EXT', K_LOCAL = '_LOCAL', K_UNKNOWN = '_UNK';

const norm = (s) => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
const NAME_TO_UF = {};
Object.keys(UFS).forEach((uf) => { NAME_TO_UF[norm(UFS[uf])] = uf; });
NAME_TO_UF['federal district'] = 'DF';
NAME_TO_UF['brasilia'] = 'DF';

function regionToUf(region) {
  let r = norm(region);
  if (!r) return null;
  if (/^[a-z]{2}$/.test(r) && UFS[r.toUpperCase()]) return r.toUpperCase();
  r = r.replace(/^(state of|estado de|estado do|estado da)\s+/, '');
  return NAME_TO_UF[r] || null;
}

// ---------------------------------------------------------------------------
// Utilitários de IP / navegador
// ---------------------------------------------------------------------------
function clientIp(req) {
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || '';
  return String(ip).replace(/^::ffff:/i, '');
}
function isPrivateIp(ip) {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb');
  }
  return true;
}
function expandIPv6(ip) {
  const [l, r] = ip.split('::');
  const left = l ? l.split(':') : [];
  const right = r !== undefined && r ? r.split(':') : [];
  const fill = r === undefined ? 0 : 8 - left.length - right.length;
  return left.concat(Array(Math.max(0, fill)).fill('0'), right);
}
function maskIp(ip) {
  if (net.isIPv4(ip)) { const p = ip.split('.'); return `${p[0]}.${p[1]}.${p[2]}.xxx`; }
  if (net.isIPv6(ip)) { const h = expandIPv6(ip); return `${h[0]}:${h[1]}:${h[2]}::xxxx`; }
  return 'desconhecido';
}
function visitorHash(ip, ua) {
  return crypto.createHmac('sha256', cfg.hashSecret()).update(`${ip}|${ua}`).digest('hex').slice(0, 16);
}
const BOT_RE = /bot|crawl|spider|slurp|facebookexternalhit|preview|headless|lighthouse|pingdom|uptime|monitor|curl\/|wget|python-requests|httpclient|axios|node-fetch|go-http/i;
function parseBrowser(ua) {
  let b = 'Outro';
  if (/Edg\//.test(ua)) b = 'Edge';
  else if (/OPR\/|Opera/.test(ua)) b = 'Opera';
  else if (/Firefox\/|FxiOS\//.test(ua)) b = 'Firefox';
  else if (/SamsungBrowser/.test(ua)) b = 'Samsung Internet';
  else if (/Chrome\/|CriOS\//.test(ua)) b = 'Chrome';
  else if (/Safari\//.test(ua)) b = 'Safari';
  return `${b} (${/Mobi|Android|iPhone|iPad/.test(ua) ? 'móvel' : 'desktop'})`;
}

// ---------------------------------------------------------------------------
// Geolocalização — chaves só no servidor, cache em memória (o IP completo nunca vai para o disco)
//   • IPinfo  (https://ipinfo.io)   — usado quando IPINFO_TOKEN existe
//   • ipwho.is (https://ipwho.is)   — HTTPS, SEM chave: fallback para funcionar "de fábrica"
// Ambos devolvem país / região / cidade APROXIMADOS (precisão de cidade, nunca de endereço).
// ---------------------------------------------------------------------------
const geoCache = new Map(); // ip completo -> { at, ttl, value }
const GEO_TTL_OK = 6 * 60 * 60 * 1000;
const GEO_TTL_FAIL = 2 * 60 * 1000;

function getJson(host, pathname, headers, timeout) {
  return new Promise((resolve) => {
    const req = https.get({ host, path: pathname, headers: { Accept: 'application/json', ...headers }, timeout: timeout || 2500 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; if (body.length > 20000) req.destroy(); });
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { resolve(null); } });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}
async function ipinfoProvider(ip) {
  const token = cfg.ipinfoToken();
  if (!token) return null;
  const g = await getJson('ipinfo.io', `/${encodeURIComponent(ip)}/json`, { Authorization: `Bearer ${token}` });
  if (!g || g.bogon) return null;
  return { provider: 'ipinfo', country: g.country, region: g.region, city: g.city };
}
async function ipwhoisProvider(ip) {
  const g = await getJson('ipwho.is', `/${encodeURIComponent(ip)}?fields=success,country_code,region,region_code,city`);
  if (!g || g.success === false) return null;
  // No Brasil, region_code costuma ser a sigla da UF; o nome do estado é o plano B (regionToUf aceita ambos)
  const region = (g.country_code === 'BR' && g.region_code) ? g.region_code : g.region;
  return { provider: 'ipwhois', country: g.country_code, region, regionName: g.region, city: g.city };
}
async function defaultProvider(ip) {
  const mode = cfg.geoMode();
  if (mode === 'off') return null;
  if (mode === 'ipinfo') return ipinfoProvider(ip);
  if (mode === 'ipwhois') return ipwhoisProvider(ip);
  return (await ipinfoProvider(ip)) || (await ipwhoisProvider(ip));
}
let geoProvider = defaultProvider;
function setGeoProvider(fn) { geoProvider = fn || defaultProvider; geoCache.clear(); }

async function resolveGeo(ip) {
  if (isPrivateIp(ip)) return { source: 'local', country: null, state: null, region: null, city: 'Rede local' };
  if (cfg.geoMode() === 'off') return { source: 'desativada', country: null, state: null, region: null, city: null };
  const hit = geoCache.get(ip);
  if (hit && Date.now() - hit.at < hit.ttl) return hit.value;
  let g = null;
  try { g = await geoProvider(ip); } catch (e) { g = null; }
  let value, ttl = GEO_TTL_OK;
  if (!g) {
    value = { source: 'indisponivel', country: null, state: null, region: null, city: null };
    ttl = GEO_TTL_FAIL;
  } else {
    const country = String(g.country || '').toUpperCase().slice(0, 2) || null;
    value = {
      source: g.provider || 'geo',
      country,
      state: country === 'BR' ? (regionToUf(g.region) || regionToUf(g.regionName)) : null,
      region: (g.regionName || g.region) ? String(g.regionName || g.region).slice(0, 80) : null,
      city: g.city ? String(g.city).slice(0, 80) : null
    };
  }
  if (geoCache.size > 5000) geoCache.clear();
  geoCache.set(ip, { at: Date.now(), ttl, value });
  return value;
}

// Em quais contadores um acesso é somado (sempre o total + exatamente um destino)
function counterKeys(geo) {
  let dest;
  if (geo.state) dest = geo.state;
  else if (geo.source === 'local') dest = K_LOCAL;
  else if (geo.country && geo.country !== 'BR') dest = K_FOREIGN;
  else dest = K_UNKNOWN;
  return [K_ALL, dest];
}
function totalsFromRows(rows) {
  const t = {};
  rows.forEach((r) => {
    const keys = counterKeys({ state: r.state, source: r.geoSource, country: r.country });
    keys.forEach((k) => { t[k] = (t[k] || 0) + 1; });
  });
  return t;
}

// ---------------------------------------------------------------------------
// Persistência: Supabase (se configurado) com fallback em arquivo local
// Duas coisas são gravadas:  registros individuais (com retenção)  +  contadores acumulados (permanentes)
// ---------------------------------------------------------------------------
class LocalStore {
  constructor() {
    this.name = 'local';
    this.rows = [];
    this.totals = {};
    this.nextId = 1;
    this.dirty = false;
    this.timer = null;
    try {
      const raw = JSON.parse(fs.readFileSync(VISITS_FILE, 'utf8'));
      if (Array.isArray(raw.visits)) {
        this.rows = raw.visits;
        this.nextId = (this.rows.reduce((m, r) => Math.max(m, r.id || 0), 0)) + 1;
      }
      if (raw.totals && typeof raw.totals === 'object') this.totals = raw.totals;
      else if (this.rows.length) { this.totals = totalsFromRows(this.rows); this.dirty = true; } // migra dados antigos
    } catch (e) { /* arquivo ainda não existe */ }
  }
  save() {
    this.dirty = true;
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = null; this.flush(); }, 500);
    if (this.timer.unref) this.timer.unref();
  }
  flush() {
    if (!this.dirty) return;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const tmp = VISITS_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify({ visits: this.rows, totals: this.totals }));
      fs.renameSync(tmp, VISITS_FILE);
      this.dirty = false;
    } catch (e) { console.warn('[RASTREAMENTO] Falha ao salvar visits.json:', e.message); }
  }
  async insert(row) {
    this.rows.push({ ...row, id: this.nextId++ });
    if (this.rows.length > 200000) this.rows.splice(0, this.rows.length - 200000); // só os registros; os contadores seguem
    this.save();
  }
  async addTotals(keys) { keys.forEach((k) => { this.totals[k] = (this.totals[k] || 0) + 1; }); this.save(); }
  async getTotals() { return { ...this.totals }; }
  async recent(limit) { return this.rows.slice(-limit).reverse(); }
  async purge(beforeIso) {
    const before = this.rows.length;
    this.rows = this.rows.filter((r) => r.ts >= beforeIso);
    if (this.rows.length !== before) this.save();
    return before - this.rows.length;
  }
}

class SupabaseStore {
  constructor(getSupabase) { this.name = 'supabase'; this.getSupabase = getSupabase; this.backfilled = false; }
  toDb(r) {
    return { ts: r.ts, ip_masked: r.ipMasked, visitor_hash: r.visitorHash, country: r.country, state: r.state,
      region: r.region, city: r.city, page: r.page, browser: r.browser, geo_source: r.geoSource };
  }
  fromDb(r) {
    return { id: r.id, ts: new Date(r.ts).toISOString(), ipMasked: r.ip_masked, visitorHash: r.visitor_hash, country: r.country,
      state: r.state, region: r.region, city: r.city, page: r.page, browser: r.browser, geoSource: r.geo_source };
  }
  async insert(row) {
    const { error } = await this.getSupabase().from('site_visits').insert(this.toDb(row));
    if (error) throw new Error(error.message);
  }
  // Incremento ATÔMICO no banco (função SQL increment_access_totals) — seguro com acessos simultâneos
  async addTotals(keys) {
    const { error } = await this.getSupabase().rpc('increment_access_totals', { p_keys: keys });
    if (error) throw new Error(error.message);
  }
  async getTotals() {
    const sb = this.getSupabase();
    const read = async () => {
      const { data, error } = await sb.from('access_totals').select('key,visits');
      if (error) throw new Error(error.message);
      const t = {};
      data.forEach((r) => { t[r.key] = Number(r.visits) || 0; });
      return t;
    };
    let t = await read();
    // Primeira execução com a tabela nova: aproveita os registros individuais que já existiam
    if (!this.backfilled && !t[K_ALL]) {
      this.backfilled = true;
      const rows = await this.listAll();
      if (rows.length) {
        const counts = totalsFromRows(rows);
        const payload = Object.keys(counts).map((k) => ({ key: k, visits: counts[k], updated_at: new Date().toISOString() }));
        const { error } = await sb.from('access_totals').upsert(payload, { onConflict: 'key', ignoreDuplicates: true });
        if (error) throw new Error(error.message);
        t = await read();
      }
    }
    this.backfilled = true;
    return t;
  }
  async listAll() {
    const sb = this.getSupabase();
    const out = [];
    for (let from = 0; from < 100000; from += 1000) {
      const { data, error } = await sb.from('site_visits').select('*').order('ts', { ascending: false }).range(from, from + 999);
      if (error) throw new Error(error.message);
      out.push(...data.map((r) => this.fromDb(r)));
      if (data.length < 1000) break;
    }
    return out;
  }
  async recent(limit) {
    const { data, error } = await this.getSupabase().from('site_visits').select('*').order('ts', { ascending: false }).limit(limit);
    if (error) throw new Error(error.message);
    return data.map((r) => this.fromDb(r));
  }
  async purge(beforeIso) {
    const { error } = await this.getSupabase().from('site_visits').delete().lt('ts', beforeIso);
    if (error) throw new Error(error.message);
    return 0;
  }
}

const localStore = new LocalStore();
let sbStore = null;
let sbFailedAt = 0;
function supa() {
  try {
    const c = require('./supabaseClient');
    if (!c.isSupabaseConfigured()) return null;
    if (sbFailedAt && Date.now() - sbFailedAt < 10 * 60 * 1000) return null; // tenta de novo após 10 min
    if (!sbStore) sbStore = new SupabaseStore(c.getSupabase);
    return sbStore;
  } catch (e) { return null; }
}
function activeStore() { return supa() || localStore; }
function markSupabaseFailure(err) {
  if (!sbFailedAt) console.warn('[RASTREAMENTO] Supabase indisponível para site_visits/access_totals (rode o bloco 5 do supabase_schema.sql). Usando arquivo local. Motivo:', err.message);
  sbFailedAt = Date.now();
}
async function storeRecord(row, keys) {
  const s = activeStore();
  if (s === localStore) { await localStore.insert(row); await localStore.addTotals(keys); return 'local'; }
  try { await s.insert(row); await s.addTotals(keys); return 'supabase'; }
  catch (e) { markSupabaseFailure(e); await localStore.insert(row); await localStore.addTotals(keys); return 'local'; }
}
async function storeTotals() {
  const s = activeStore();
  if (s === localStore) return { store: s, totals: await localStore.getTotals() };
  try { return { store: s, totals: await s.getTotals() }; }
  catch (e) { markSupabaseFailure(e); return { store: localStore, totals: await localStore.getTotals() }; }
}
async function storeRecent(limit) {
  const s = activeStore();
  if (s === localStore) return localStore.recent(limit);
  try { return await s.recent(limit); } catch (e) { markSupabaseFailure(e); return localStore.recent(limit); }
}
async function purgeExpired() {
  const before = new Date(Date.now() - cfg.retentionDays * 86400000).toISOString();
  let removed = 0;
  try { removed += await localStore.purge(before); } catch (e) { /* ignora */ }
  const s = supa();
  if (s) { try { await s.purge(before); } catch (e) { markSupabaseFailure(e); } }
  return removed; // contadores acumulados NÃO são apagados
}

// ---------------------------------------------------------------------------
// Tempo real: Server-Sent Events (somente administradores)
// ---------------------------------------------------------------------------
const sseClients = new Set();
function broadcast(event) {
  for (const res of sseClients) {
    try { res.write(`event: ${event}\ndata: {}\n\n`); } catch (e) { sseClients.delete(res); }
  }
}
function sseHandler(req, res) {
  if (sseClients.size >= 50) return res.status(503).json({ success: false, error: 'Muitas conexões em tempo real abertas.' });
  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();
  res.write('retry: 4000\n\n: conectado\n\n');
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
}

// ---------------------------------------------------------------------------
// Registro de acessos (beacon público) + "online agora"
// ---------------------------------------------------------------------------
const online = new Map();      // visitorHash -> { ts, page }
const lastView = new Map();    // visitorHash|page -> ts
const rate = new Map();        // ip -> { n, reset }

function pruneMaps() {
  const now = Date.now();
  for (const [k, v] of online) if (now - v.ts > cfg.onlineWindowMs) online.delete(k);
  for (const [k, v] of lastView) if (now - v > 10 * 60 * 1000) lastView.delete(k);
  for (const [k, v] of rate) if (now > v.reset) rate.delete(k);
}

async function handleTrack(req, res) {
  res.status(204).end(); // responde primeiro: o rastreamento nunca atrasa nem quebra o site
  try {
    if (req.headers.dnt === '1' || req.headers['sec-gpc'] === '1') return;
    const origin = req.headers.origin;
    if (origin) { let host = ''; try { host = new URL(origin).host; } catch (e) { return; } if (host !== req.headers.host) return; }
    const ua = String(req.headers['user-agent'] || '').slice(0, 300);
    if (!ua || BOT_RE.test(ua)) return;
    const body = req.body || {};
    const page = String(body.page || '');
    const type = body.type === 'ping' ? 'ping' : 'view';
    if (!PAGES[page]) return;

    const ip = clientIp(req);
    if (!ip) return;
    const now = Date.now();
    const rl = rate.get(ip) || { n: 0, reset: now + 60000 };
    if (now > rl.reset) { rl.n = 0; rl.reset = now + 60000; }
    rl.n++; rate.set(ip, rl);
    if (rl.n > 120) return;
    if (online.size > 20000) pruneMaps();

    const vh = visitorHash(ip, ua);
    online.set(vh, { ts: now, page });
    if (type === 'ping') return;

    const key = `${vh}|${page}`;
    if (lastView.has(key) && now - lastView.get(key) < 30000) return;
    lastView.set(key, now);

    const geo = await resolveGeo(ip);
    await storeRecord({
      ts: new Date(now).toISOString(),
      ipMasked: isPrivateIp(ip) ? 'rede local' : (cfg.storeFullIp ? ip : maskIp(ip)),
      visitorHash: vh,
      country: geo.country, state: geo.state, region: geo.region, city: geo.city,
      page, browser: parseBrowser(ua), geoSource: geo.source
    }, counterKeys(geo));
    broadcast('visit');
  } catch (e) {
    console.warn('[RASTREAMENTO] Falha ao registrar acesso:', e.message);
  }
}

// ---------------------------------------------------------------------------
// Consulta para o painel da página inicial
// ---------------------------------------------------------------------------
function onlineNow() {
  const now = Date.now();
  let n = 0;
  for (const v of online.values()) if (now - v.ts <= cfg.onlineWindowMs) n++;
  return n;
}

function toRowDto(r) {
  const pg = PAGES[r.page];
  return {
    id: r.id, ts: r.ts, ip: r.ipMasked || '—', country: r.country || null,
    state: r.state || null, stateName: r.state ? UFS[r.state] : null,
    city: r.city || null, region: r.region || null,
    page: pg ? pg.label : r.page, browser: r.browser || null, geoSource: r.geoSource || null
  };
}

function computeHome(totals, recentRows, extra) {
  const all = totals[K_ALL] || 0;
  const ranked = Object.keys(UFS).map((uf) => ({ uf, name: UFS[uf], visits: totals[uf] || 0 }))
    .sort((a, b) => b.visits - a.visits || a.name.localeCompare(b.name, 'pt-BR'));
  let rank = 0;
  const states = ranked.map((s) => ({
    ...s,
    percent: all ? Math.round((s.visits / all) * 1000) / 10 : 0,
    rank: s.visits > 0 ? ++rank : null
  }));
  const reached = states.filter((s) => s.visits > 0).length;
  const top = states[0] && states[0].visits > 0 ? states[0] : null;
  return {
    totals: {
      visits: all,
      statesReached: reached,
      topState: top ? { uf: top.uf, name: top.name, visits: top.visits } : null,
      onlineNow: extra.onlineNow
    },
    outside: { foreign: totals[K_FOREIGN] || 0, local: totals[K_LOCAL] || 0, unknown: totals[K_UNKNOWN] || 0 },
    states,
    recent: recentRows.map(toRowDto)
  };
}

// ---------------------------------------------------------------------------
// Forma do mapa (contornos reais via pacote @svg-maps/brazil; sem ele o front usa um mapa em grade)
// ---------------------------------------------------------------------------
let shapeCache = null;
async function loadShape() {
  if (shapeCache) return shapeCache;
  try {
    const mod = await import('@svg-maps/brazil');
    const m = (mod && mod.default) || mod;
    if (m && Array.isArray(m.locations) && m.viewBox) {
      const locations = m.locations
        .map((l) => ({ uf: String(l.id || '').toUpperCase(), name: l.name, path: l.path }))
        .filter((l) => UFS[l.uf] && typeof l.path === 'string');
      if (locations.length === 27) {
        shapeCache = { fallback: false, viewBox: m.viewBox, locations, attribution: 'Mapa: MapSVG / @svg-maps/brazil (CC BY 4.0)' };
      }
    }
  } catch (e) { /* pacote não instalado: usa o mapa em grade */ }
  if (!shapeCache) shapeCache = { fallback: true };
  return shapeCache;
}

// ---------------------------------------------------------------------------
// Rotas
// ---------------------------------------------------------------------------
function mount(app, { requireAdminAuth }) {
  app.post('/api/track', handleTrack);
  app.get('/api/track/policy', (req, res) => res.json({ success: true, retentionDays: cfg.retentionDays }));

  const r = express.Router();
  r.use(requireAdminAuth);
  const wrap = (fn) => async (req, res) => {
    try { await fn(req, res); } catch (e) {
      console.warn('[RASTREAMENTO]', e.message);
      if (!res.headersSent) res.status(500).json({ success: false, error: 'Erro ao consultar o rastreamento.' });
    }
  };

  r.get('/home', wrap(async (req, res) => {
    const limit = Math.min(50, Math.max(5, parseInt(req.query.limit, 10) || 15));
    const { store, totals } = await storeTotals();
    const recent = await storeRecent(limit);
    const mode = cfg.geoMode();
    res.set('Cache-Control', 'no-store');
    res.json({
      success: true,
      updatedAt: new Date().toISOString(),
      ...computeHome(totals, recent, { onlineNow: onlineNow() }),
      config: {
        storage: store.name,
        geoMode: mode,
        geoProvider: mode === 'off' ? 'desativada' : (mode === 'ipwhois' || (mode === 'auto' && !cfg.ipinfoToken()) ? 'ipwho.is' : 'IPinfo'),
        retentionDays: cfg.retentionDays,
        storesFullIp: cfg.storeFullIp,
        trustProxy: Boolean(req.app.get('trust proxy'))
      }
    });
  }));

  r.get('/map-shape', wrap(async (req, res) => {
    res.json({ success: true, ...(await loadShape()) });
  }));

  r.get('/stream', sseHandler);

  app.use('/api/tracking', r);

  purgeExpired().catch(() => {});
  const t = setInterval(() => { purgeExpired().catch(() => {}); pruneMaps(); }, 6 * 3600 * 1000);
  if (t.unref) t.unref();
  const hb = setInterval(() => { for (const c of sseClients) { try { c.write(': ping\n\n'); } catch (e) { sseClients.delete(c); } } }, 25000);
  if (hb.unref) hb.unref();
  process.on('exit', () => { try { localStore.flush(); } catch (e) { /* noop */ } });
}

module.exports = {
  mount, setGeoProvider, regionToUf, maskIp, isPrivateIp, parseBrowser, computeHome, counterKeys, UFS,
  _internal: { localStore, online, handleTrack, resolveGeo, storeTotals, storeRecent, sseClients, totalsFromRows }
};
