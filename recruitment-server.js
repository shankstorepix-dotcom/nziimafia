'use strict';
/**
 * NZI — Recrutamento (candidaturas para a tag da NZI)
 *
 * Rotas
 *   POST  /api/recruitment/apply        público   envia uma candidatura { nick, requirement, requirementText }
 *   GET   /api/admin/recruitment        admin     lista candidaturas (Dono/Fundador)
 *   PATCH /api/admin/recruitment/:id    admin     muda o status: pendente | aprovado | recusado
 *
 * Como a candidatura é guardada de verdade (nada é simulado)
 *   1. Supabase (tabela public.recruitment_applications, bloco 6 do supabase_schema.sql) — recomendado,
 *      obrigatório na Vercel porque o disco de lá é somente leitura/efêmero.
 *   2. Arquivo local data/recruitment.json — só em ambiente com disco gravável (desenvolvimento local).
 *   3. Webhook do Discord (RECRUITMENT_DISCORD_WEBHOOK) — aviso opcional para a equipe. A URL fica SÓ no servidor.
 *      Se ele for o único canal configurado, ele conta como entrega real.
 *  Se nenhum canal conseguir receber a candidatura, a API responde 503 e o site mostra erro:
 *  o visitante nunca vê "sucesso" para uma candidatura que não foi salva.
 *
 * Segurança
 *  - Validação rigorosa no servidor (o limite de 15 caracteres do front-end é só conveniência).
 *  - O requisito é identificado pelo número (1–8); o texto vindo do navegador é só informativo e é sanitizado.
 *  - Proteção anti-CSRF do projeto continua valendo (POST exige mesma origem).
 *  - Rate limit por IP, campo isca (honeypot) e bloqueio de candidatura pendente duplicada para o mesmo nick.
 *  - Guarda apenas IP truncado + hash HMAC do visitante (mesma política do rastreamento / LGPD).
 *  - Nenhum token ou credencial vai para o front-end.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const https = require('https');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
const LOCAL_FILE = path.join(DATA_DIR, 'recruitment.json');
const TABLE = 'recruitment_applications';

const NICK_MAX = 15;
const REQUIREMENT_COUNT = 7;
const STATUSES = ['pendente', 'aprovado', 'recusado'];

const RATE_FLOOD_MAX = 40;           // requisições (válidas ou não) por IP a cada 10 min
const RATE_MAX = 3;                  // candidaturas válidas por IP...
const RATE_WINDOW_MS = 10 * 60 * 1000; // ...a cada 10 minutos
const rate = new Map();              // ip -> { n, reset } (em memória: melhor esforço em serverless)

const webhookUrl = () => (process.env.RECRUITMENT_DISCORD_WEBHOOK || '').trim();
const hashSecret = () => process.env.TRACKING_HASH_SECRET || process.env.JWT_SECRET || 'nzi-recruitment-secret';

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------
function clientIp(req) {
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || '';
  return String(ip).replace(/^::ffff:/i, '');
}
function maskIp(ip) {
  if (net.isIPv4(ip)) { const p = ip.split('.'); return `${p[0]}.${p[1]}.${p[2]}.xxx`; }
  if (net.isIPv6(ip)) { const h = ip.split(':'); return `${h[0] || '0'}:${h[1] || '0'}:${h[2] || '0'}::xxxx`; }
  return 'desconhecido';
}
function visitorHash(ip, ua) {
  return crypto.createHmac('sha256', hashSecret()).update(`${ip}|${ua}`).digest('hex').slice(0, 16);
}

// Remove caracteres de controle/invisíveis e normaliza espaços.
function cleanText(value, max) {
  return String(value == null ? '' : value)
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

// Nick: 1–15 caracteres; letras, números, espaço (no meio), _ . - [ ]
const NICK_RE = /^[\p{L}\p{N}_.\-\[\] ]+$/u;

function validate(body) {
  const errors = {};
  const nickRaw = typeof body.nick === 'string' ? body.nick : '';
  const nick = cleanText(nickRaw, 200);

  if (!nick) errors.nick = 'Informe o seu nick.';
  else if ([...nick].length > NICK_MAX) errors.nick = `O nick deve ter no máximo ${NICK_MAX} caracteres.`;
  else if (!NICK_RE.test(nick)) errors.nick = 'Use apenas letras, números, espaço e os símbolos _ . - [ ].';

  const reqId = Number(body.requirement);
  if (!Number.isInteger(reqId) || reqId < 1 || reqId > REQUIREMENT_COUNT) {
    errors.requirement = 'Escolha exatamente um requisito.';
  }

  return {
    errors,
    ok: Object.keys(errors).length === 0,
    value: {
      nick,
      requirementId: reqId,
      // texto do requisito exibido na página no momento do envio (informativo; o número é o dado confiável)
      requirementText: cleanText(body.requirementText, 300)
    }
  };
}

// ---------------------------------------------------------------------------
// Armazenamento
// ---------------------------------------------------------------------------
function supa() {
  try {
    const c = require('./supabaseClient');
    return c.isSupabaseConfigured() ? c.getSupabase() : null;
  } catch (e) { return null; }
}

const onVercel = () => Boolean(process.env.VERCEL);

const localStore = {
  available() { return !onVercel(); },
  read() {
    try { return JSON.parse(fs.readFileSync(LOCAL_FILE, 'utf8')).applications || []; }
    catch (e) { return []; }
  },
  write(rows) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = `${LOCAL_FILE}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ applications: rows }, null, 2));
    fs.renameSync(tmp, LOCAL_FILE);
  },
  insert(row) {
    const rows = this.read();
    const dup = rows.some((r) => r.status === 'pendente' && r.nick.toLowerCase() === row.nick.toLowerCase());
    if (dup) { const e = new Error('duplicate'); e.code = 'DUPLICATE'; throw e; }
    const id = rows.reduce((m, r) => Math.max(m, Number(r.id) || 0), 0) + 1;
    const saved = { id, ...row };
    rows.push(saved);
    this.write(rows);
    return saved;
  },
  list(limit) { return this.read().slice().reverse().slice(0, limit); },
  setStatus(id, status) {
    const rows = this.read();
    const r = rows.find((x) => String(x.id) === String(id));
    if (!r) return null;
    r.status = status; r.reviewed_at = new Date().toISOString();
    this.write(rows);
    return r;
  }
};

const dbStore = {
  async insert(client, row) {
    const { data, error } = await client.from(TABLE).insert(row).select('id').single();
    if (error) {
      if (error.code === '23505') { const e = new Error('duplicate'); e.code = 'DUPLICATE'; throw e; }
      throw new Error(error.message);
    }
    return data;
  },
  async list(client, limit) {
    const { data, error } = await client.from(TABLE).select('*').order('created_at', { ascending: false }).limit(limit);
    if (error) throw new Error(error.message);
    return data || [];
  },
  async setStatus(client, id, status) {
    const { data, error } = await client.from(TABLE)
      .update({ status, reviewed_at: new Date().toISOString() }).eq('id', id).select('*').maybeSingle();
    if (error) throw new Error(error.message);
    return data;
  }
};

// Grava no armazenamento durável disponível. Retorna { saved, id } ou lança erro.
async function persist(row) {
  const client = supa();
  if (client) {
    const r = await dbStore.insert(client, row);
    return { saved: true, id: r && r.id, where: 'supabase' };
  }
  if (localStore.available()) {
    const r = localStore.insert(row);
    return { saved: true, id: r.id, where: 'local' };
  }
  return { saved: false };
}

// ---------------------------------------------------------------------------
// Webhook do Discord (opcional, só no servidor)
// ---------------------------------------------------------------------------
function postWebhook(urlStr, payload) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return resolve(false); }
    if (u.protocol !== 'https:') return resolve(false);
    const body = JSON.stringify(payload);
    const req = https.request({
      method: 'POST', host: u.host, path: u.pathname + u.search, timeout: 4000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => { res.resume(); resolve(res.statusCode >= 200 && res.statusCode < 300); });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end(body);
  });
}

function notifyDiscord(app, protocol) {
  const url = webhookUrl();
  if (!url) return Promise.resolve(null);
  return postWebhook(url, {
    username: 'NZI Recrutamento',
    allowed_mentions: { parse: [] }, // nunca marca @everyone/@cargos com texto vindo de visitantes
    embeds: [{
      title: 'Nova candidatura — Recrutamento NZI',
      color: 0xff2a3a,
      fields: [
        { name: 'Nick', value: '`' + app.nick.replace(/`/g, "'") + '`', inline: true },
        { name: 'Requisito', value: `#${app.requirementId}${app.requirementText ? ' — ' + app.requirementText : ''}`.slice(0, 1000) },
        ...(protocol ? [{ name: 'Protocolo', value: String(protocol), inline: true }] : [])
      ],
      timestamp: new Date().toISOString()
    }]
  });
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
// Dois limites por IP: um folgado para qualquer requisição (barra flood) e outro estrito só para
// candidaturas VÁLIDAS (barra spam sem punir quem erra o formulário).
function rateLimited(ip, bucket, max) {
  const now = Date.now();
  if (rate.size > 5000) for (const [k, v] of rate) if (now > v.reset) rate.delete(k);
  const key = `${bucket}:${ip}`;
  const r = rate.get(key) || { n: 0, reset: now + RATE_WINDOW_MS };
  if (now > r.reset) { r.n = 0; r.reset = now + RATE_WINDOW_MS; }
  r.n++; rate.set(key, r);
  return r.n > max ? Math.ceil((r.reset - now) / 1000) : 0;
}
function tooMany(res, wait) {
  res.set('Retry-After', String(wait));
  return res.status(429).json({ success: false, error: `Muitas tentativas. Aguarde ${Math.max(1, Math.ceil(wait / 60))} min e tente novamente.` });
}

async function handleApply(req, res) {
  res.set('Cache-Control', 'no-store');
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};

    // honeypot: humanos nunca preenchem este campo
    if (typeof body.website === 'string' && body.website.trim() !== '') {
      return res.status(400).json({ success: false, error: 'Não foi possível enviar a candidatura.' });
    }

    const ip = clientIp(req) || 'desconhecido';
    const floodWait = rateLimited(ip, 'all', RATE_FLOOD_MAX);
    if (floodWait) return tooMany(res, floodWait);

    const v = validate(body);
    if (!v.ok) {
      return res.status(400).json({ success: false, error: Object.values(v.errors)[0], fields: v.errors });
    }

    const applyWait = rateLimited(ip, 'apply', RATE_MAX);
    if (applyWait) return tooMany(res, applyWait);

    const ua = String(req.headers['user-agent'] || '').slice(0, 300);
    const row = {
      nick: v.value.nick,
      requirement_id: v.value.requirementId,
      requirement_text: v.value.requirementText,
      status: 'pendente',
      ip_masked: maskIp(ip),
      visitor_hash: visitorHash(ip, ua),
      created_at: new Date().toISOString()
    };

    let result = { saved: false };
    let storeError = null;
    try {
      result = await persist(row);
    } catch (e) {
      if (e && e.code === 'DUPLICATE') {
        return res.status(409).json({ success: false, error: 'Já existe uma candidatura pendente para este nick.', fields: { nick: 'Já existe uma candidatura pendente para este nick.' } });
      }
      storeError = e;
      console.error('[RECRUTAMENTO] Falha ao gravar candidatura:', e.message);
    }

    const hook = await notifyDiscord(v.value, result.id).catch(() => false);

    if (!result.saved && hook !== true) {
      if (!storeError && !webhookUrl()) {
        console.error('[RECRUTAMENTO] Nenhum destino configurado. Configure o Supabase (bloco 6 do schema) ou RECRUITMENT_DISCORD_WEBHOOK.');
      }
      return res.status(503).json({ success: false, error: 'O recrutamento está indisponível no momento. Tente novamente mais tarde.' });
    }

    return res.status(201).json({
      success: true,
      message: 'Candidatura enviada para análise da equipe.',
      protocol: result.saved && result.id != null ? result.id : null
    });
  } catch (err) {
    console.error('[RECRUTAMENTO] Erro inesperado:', err);
    return res.status(500).json({ success: false, error: 'Erro interno ao enviar a candidatura.' });
  }
}

async function handleList(req, res) {
  try {
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const client = supa();
    const rows = client ? await dbStore.list(client, limit) : localStore.list(limit);
    res.set('Cache-Control', 'no-store');
    res.json({ success: true, count: rows.length, applications: rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function handleSetStatus(req, res) {
  try {
    const status = String((req.body && req.body.status) || '').toLowerCase();
    if (!STATUSES.includes(status)) {
      return res.status(400).json({ success: false, error: `Status inválido. Use: ${STATUSES.join(', ')}.` });
    }
    const id = String(req.params.id || '');
    if (!/^\d{1,12}$/.test(id)) return res.status(400).json({ success: false, error: 'ID inválido.' });
    const client = supa();
    const row = client ? await dbStore.setStatus(client, id, status) : localStore.setStatus(id, status);
    if (!row) return res.status(404).json({ success: false, error: 'Candidatura não encontrada.' });
    res.json({ success: true, application: row });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

function mount(app, { requireAdminAuth }) {
  app.post('/api/recruitment/apply', handleApply);
  app.get('/api/admin/recruitment', requireAdminAuth, handleList);
  app.patch('/api/admin/recruitment/:id', requireAdminAuth, handleSetStatus);
}

module.exports = { mount, validate, cleanText, NICK_MAX, REQUIREMENT_COUNT, _internal: { localStore, handleApply, rate } };
