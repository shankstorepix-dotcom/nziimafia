require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const db = require('./db');
const {
  validatePinFormat,
  validatePassword,
  getClientIp,
  generateMemberToken,
  verifyMemberToken,
  generateLoginTicket,
  verifyLoginTicket,
  getLoginAttemptsLeft,
  checkLoginRateLimit,
  recordLoginFailure,
  clearLoginFailures,
  checkActionRateLimit,
  recordActionFailure,
  clearActionFailures,
  requireMemberAuth,
  requireMinLevel,
  requireAdminAuth,
  optionalMemberAuth,
  requireCsrfProtection,
  sanitizeUrl,
  verifyMember2FA
} = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Oculta cabeçalho 'X-Powered-By: Express'
app.disable('x-powered-by');

// Configuração para proxies reversos / CDN (Cloudflare e Vercel):
// Permite que o Express confie nos cabeçalhos de proxy para extração de IP real e HTTPS
if (process.env.TRUST_PROXY) {
  const tp = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : (tp === 'true' ? 1 : tp));
} else {
  // Padrão seguro para ambiente Cloudflare + Vercel
  app.set('trust proxy', 1);
}

// Configuração de segurança HTTP avançada (Helmet & CSP)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'"],
      // Spotify embed (iframe) + mídia
      frameSrc: ["'self'", "https://open.spotify.com", "https://spotify.com"],
      childSrc: ["'self'", "https://open.spotify.com"],
      mediaSrc: ["'self'", "https:", "blob:", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Configuração restritiva de CORS (apenas localhost/127.0.0.1 em dev ou ALLOWED_ORIGINS em produção)
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim().toLowerCase())
  : [];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    try {
      const parsed = new URL(origin);
      const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
      if (isLocalhost || allowedOrigins.includes(origin.toLowerCase())) {
        return callback(null, true);
      }
    } catch (_) {}
    return callback(null, false);
  },
  credentials: true
}));

// ==========================================
// PROTEÇÃO ANTI-DDOS: RATE LIMITER GLOBAL POR IP
// ==========================================
// Bloqueia qualquer IP que faça mais de 120 requisições em 60 segundos (todas as rotas)
// Limite separado e mais rígido para rotas de autenticação (20 req / 60s)
const globalRateLimitMap = new Map();
const authRateLimitMap = new Map();

function pruneRateMaps() {
  const now = Date.now();
  const expiry = 120000; // 2 min
  for (const [k, v] of globalRateLimitMap.entries()) {
    if (now - v.windowStart > expiry) globalRateLimitMap.delete(k);
  }
  for (const [k, v] of authRateLimitMap.entries()) {
    if (now - v.windowStart > expiry) authRateLimitMap.delete(k);
  }
}
const _pruneRateTimer = setInterval(pruneRateMaps, 60000);
if (_pruneRateTimer.unref) _pruneRateTimer.unref();

function getIpForRateLimit(req) {
  const cf = req.headers['cf-connecting-ip'] || req.headers['true-client-ip'];
  if (cf) return cf.split(',')[0].trim();
  const xff = req.headers['x-forwarded-for'] || req.headers['x-vercel-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || req.ip || '127.0.0.1';
}

// Middleware: Rate limit global (120 req/min por IP)
app.use((req, res, next) => {
  const ip = getIpForRateLimit(req);
  const now = Date.now();
  const windowMs = 60000;
  const maxGlobal = 120;

  let record = globalRateLimitMap.get(ip);
  if (!record || now - record.windowStart > windowMs) {
    record = { count: 1, windowStart: now };
    globalRateLimitMap.set(ip, record);
  } else {
    record.count++;
  }

  if (record.count > maxGlobal) {
    const retryAfter = Math.ceil((record.windowStart + windowMs - now) / 1000);
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({
      success: false,
      error: `Limite de requisições excedido. Aguarde ${retryAfter}s.`
    });
  }

  // Rate limit mais rígido para rotas de autenticação (20 req/min)
  if (req.path.startsWith('/api/auth/')) {
    const maxAuth = 20;
    let authRecord = authRateLimitMap.get(ip);
    if (!authRecord || now - authRecord.windowStart > windowMs) {
      authRecord = { count: 1, windowStart: now };
      authRateLimitMap.set(ip, authRecord);
    } else {
      authRecord.count++;
    }
    if (authRecord.count > maxAuth) {
      const retryAfter = Math.ceil((authRecord.windowStart + windowMs - now) / 1000);
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({
        success: false,
        error: `Muitas tentativas de autenticação. Bloqueado por ${retryAfter}s.`
      });
    }
  }

  next();
});

// ==========================================
// ANTI-SLOWLORIS & PAYLOAD HARDENING
// ==========================================
// Proteção contra payload excessivo (DDoS / Memory exhaustion)
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());

// Bloqueia requests com cabeçalhos absurdamente grandes (anti-DDoS via header flooding)
app.use((req, res, next) => {
  const headerSize = JSON.stringify(req.headers).length;
  if (headerSize > 16384) { // 16KB max headers
    return res.status(431).json({ success: false, error: 'Request Header Fields Too Large' });
  }
  next();
});

// Proteção Anti-CSRF para rotas de mutação
app.use(requireCsrfProtection);

// ==========================================
// HEADERS DE SEGURANÇA ADICIONAIS (ANTI-DEFACEMENT)
// ==========================================
app.use((req, res, next) => {
  // Impede que o site seja embutido em frames de outros domínios (anti-clickjacking / anti-deface)
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  // Bloqueia detecção automática de MIME type (evita injeção de scripts via content-type sniffing)
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Ativa proteção contra XSS reflexivo no navegador
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Impede que o Referrer vaze informações para domínios externos
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Bloqueia APIs sensíveis do navegador que não são necessárias
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  // Anti-cache para respostas de API (evita que proxies/CDN armazenem dados sensíveis)
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// ==========================================
// PROTEÇÃO RIGOROSA DE ARQUIVOS INTERNOS E BANCO DE DADOS
// ==========================================
// Bloqueia qualquer tentativa de download de arquivos confidenciais do servidor:
// .json, .sql, .env, .txt, .md, scripts backend, diretório data/, .git, etc.
const SENSITIVE_EXTS = ['.env','.git','.sql','.json','.md','.txt','.bak','.log','.old','.orig','.save'];
const SENSITIVE_FILES = ['database.json','package.json','package-lock.json','vercel.json','LEIA-ME',
  'server.js','db.js','auth.js','supabaseClient.js','supabaseDb.js','tracking-server.js',
  'recruitment-server.js','migrate-to-supabase.js','test_security.js','.env','.gitignore'];
const SENSITIVE_DIRS = ['/data','/assets','/node_modules','/.git'];

function isSensitivePath(p) {
  const lower = p.toLowerCase();
  // Bloqueia diretórios sensíveis
  for (const d of SENSITIVE_DIRS) {
    if (lower === d || lower.startsWith(d + '/')) return true;
  }
  // Bloqueia arquivos sensíveis por nome
  const basename = lower.split('/').pop();
  for (const f of SENSITIVE_FILES) {
    if (basename === f.toLowerCase()) return true;
  }
  // Bloqueia extensões sensíveis
  for (const ext of SENSITIVE_EXTS) {
    if (lower.endsWith(ext)) return true;
  }
  return false;
}

app.use((req, res, next) => {
  let p = req.path;
  // Double decode para prevenir bypass via %252e%252e
  try { p = decodeURIComponent(p); } catch (e) {}
  try { p = decodeURIComponent(p); } catch (e) {}
  
  // Normaliza barras repetidas
  p = p.replace(/\/+/g, '/');

  // Bloqueia path traversal (../ em qualquer forma)
  if (p.includes('..') || req.path.includes('..') || /%2e%2e/i.test(req.path) || /%252e/i.test(req.path)) {
    return res.status(403).send('Forbidden');
  }

  if (isSensitivePath(p)) {
    return res.status(404).send('Not found');
  }
  next();
});

// Whitelist estrita de arquivos estáticos públicos legítimos do frontend
const PUBLIC_STATIC_FILES = new Set([
  'nzi-theme.css',
  'recruitment.css',
  'tracking.css',
  'blood-cursor.js',
  'recruitment.js',
  'tracking.js',
  'public-tracking.js',
  'mrrobot.gif',
  'dashboard-hero.gif',
  'nzi-header.png',
  'favicon.ico',
  'robots.txt'
]);

app.use((req, res, next) => {
  const cleanPath = req.path.replace(/^\/+/, '').toLowerCase();
  if (PUBLIC_STATIC_FILES.has(cleanPath)) {
    const filePath = path.join(__dirname, cleanPath);
    if (fs.existsSync(filePath)) {
      return res.sendFile(filePath);
    }
    if (cleanPath === 'favicon.ico') {
      return res.status(204).end();
    }
    return res.status(404).end();
  }
  next();
});

// ==========================================
// ROTAS DE PÁGINAS HTML & NAVEGAÇÃO
// ==========================================

// Página inicial (Hierarquia e apresentação pública da Nzi Mafia)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Site único: Início, Entretenimento e Login são abas do index.html
app.get('/acesso', (req, res) => res.redirect('/#login'));
app.get('/entretenimento', (req, res) => res.redirect('/#entretenimento'));
app.get('/recrutamento', (req, res) => res.redirect('/#recrutamento'));

// Login: se já tem sessão válida, vai direto ao dashboard
app.get('/login', (req, res) => {
  const token = req.cookies && req.cookies.nzi_token;
  if (token && verifyMemberToken(token)) return res.redirect('/dashboard');
  res.redirect('/#login');
});

// Dashboard NZI: só abre com sessão válida; sem login volta para a aba Login
app.get('/dashboard', (req, res) => {
  const token = req.cookies && req.cookies.nzi_token;
  if (!token || !verifyMemberToken(token)) return res.redirect('/#login');
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// ==========================================
// ROTAS DE AUTENTICAÇÃO (LOGIN COM PIN DE 6 DÍGITOS)
// ==========================================

// Status da Conexão com o Supabase
app.get('/api/supabase/status', async (req, res) => {
  const isConfigured = db.isSupabaseConfigured();
  if (!isConfigured) {
    return res.json({
      success: true,
      configured: false,
      connected: false,
      message: "Supabase não configurado. Operando com armazenamento local (data/database.json).",
      instructions: "Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY no arquivo .env para ativar a nuvem."
    });
  }

  const test = await db.testSupabaseConnection();
  let stats = null;
  if (test.connected) {
    try {
      stats = await db.supabaseDb.getDashboardStats();
    } catch (e) {}
  }

  res.json({
    success: true,
    configured: true,
    connected: test.connected,
    message: test.message,
    error: test.error,
    stats
  });
});

// Diagnóstico rápido (sem dados sensíveis — protegido contra enumeração)
app.get('/api/health', (req, res) => {
  try {
    const database = db.getDb();
    const members = (database && database.members) || [];
    res.json({
      success: true,
      ok: true,
      membersCount: members.length,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// Lista de codinomes para o seletor da tela de login (sem dados confidenciais)
app.get('/api/members/public', async (req, res) => {
  try {
    let members = [];
    if (db.isSupabaseConfigured()) {
      try {
        members = await db.supabaseDb.getMembers();
      } catch (e) {
        console.warn('[members/public] supabase:', e.message);
      }
    }
    if (!members || members.length === 0) {
      try {
        members = (db.getDb() || {}).members || [];
      } catch (e) {
        console.warn('[members/public] local db:', e.message);
        members = [];
      }
    }
    const publicMembers = (members || []).map(m => ({
      id: m.id,
      username: m.username,
      name: m.name,
      role: m.role,
      level: m.level
    }));
    return res.json({ success: true, members: publicMembers });
  } catch (err) {
    console.error('[members/public]', err);
    return res.status(500).json({ success: false, error: 'Erro ao listar membros.', detail: String(err.message || err) });
  }
});

// ==========================================
// FLUXO DE LOGIN EM DUAS ETAPAS (COM PIN KEYPAD)
// ==========================================

// Etapa 1: Validação de Usuário e Senha ao apertar "Entrar" -> libera a tela do PIN Keypad
async function handleLoginStep1(req, res) {
  try {
    const { username, password, hwid } = req.body || {};
    const ip = getClientIp(req);

    // 1. Rate limiting por IP e Usuário
    const rateCheck = checkLoginRateLimit(ip, username);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        success: false,
        error: rateCheck.error
      });
    }

    // 2. Validação básica de campos
    if (!username || typeof username !== 'string' || !username.trim()) {
      return res.status(400).json({
        success: false,
        error: "Acesso restrito apenas para membros. Informe seu codinome de usuário."
      });
    }

    if (!password || typeof password !== 'string' || !password.trim()) {
      return res.status(400).json({
        success: false,
        error: "Acesso restrito apenas para membros. Informe sua senha de acesso."
      });
    }

    // 3. Busca do membro
    let member = null;
    if (db.isSupabaseConfigured()) {
      try {
        member = await db.supabaseDb.findMember(username.trim());
      } catch (e) {}
    }
    if (!member) {
      member = db.findMember(username.trim());
    }

    if (!member) {
      recordLoginFailure(ip, username);
      db.recordLogin(username, ip, false, "LOGIN_FALHA_USUARIO", hwid || null);
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros. Credenciais inválidas (usuário ou senha incorretos)."
      });
    }

    if (member.status === 'bloqueado' || member.status === 'banido' || member.status === 'inativo') {
      db.recordLogin(member.username, ip, false, "LOGIN_STATUS_BLOQUEADO", hwid || null);
      return res.status(403).json({
        success: false,
        error: "🔒 Acesso bloqueado: Esta conta está suspensa na Nzi Mafia."
      });
    }

    // 4. Verificação de senha
    const passwordValid = db.verifyMemberPassword(member, password.trim());
    if (!passwordValid) {
      recordLoginFailure(ip, member.username);
      db.recordLogin(member.username, ip, false, "LOGIN_SENHA_INCORRETA", hwid || null);
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros. Credenciais inválidas (usuário ou senha incorretos)."
      });
    }

    // 5. Verificação de IP / HWID prévia
    const ipCheck = db.checkMemberIp(member, ip);
    if (!ipCheck.allowed) {
      db.recordLogin(member.username, ip, false, "LOGIN_IP_BLOQUEADO", hwid || null);
      return res.status(403).json({
        success: false,
        error: `🔒 IP Bloqueado: ${ipCheck.reason} Contate um administrador para liberar seu acesso.`,
        blocked: 'ip'
      });
    }

    if (hwid) {
      const hwidCheck = db.checkMemberHwid(member, hwid);
      if (!hwidCheck.allowed) {
        db.recordLogin(member.username, ip, false, "LOGIN_DISPOSITIVO_BLOQUEADO", hwid);
        return res.status(403).json({
          success: false,
          error: `🔒 Dispositivo Bloqueado: ${hwidCheck.reason} Contate um administrador para liberar seu acesso.`,
          blocked: 'hwid'
        });
      }
    }

    // 6. Sucesso no Passo 1: Emite ticket assinado de curta duração (5 min) para liberar a tela do PIN Keypad
    const ticket = generateLoginTicket(member);

    return res.json({
      success: true,
      requirePin: true,
      pinLength: 6,
      ticket: ticket,
      member: {
        username: member.username,
        name: member.name,
        role: member.role
      }
    });
  } catch (err) {
    console.error('[auth/login/step1]', err);
    return res.status(500).json({
      success: false,
      error: 'Erro interno ao validar credenciais. Tente novamente.'
    });
  }
}

// Etapa 2: Validação do PIN digitado no Keypad
async function handleVerifyPin(req, res) {
  try {
    const { ticket, pin, code, otp, hwid, username, password } = req.body || {};
    const ip = getClientIp(req);
    const pinEntered = (pin || code || otp || '').toString().trim();

    // 1. Resolução do membro autenticado pelo ticket ou credenciais de fallback
    let member = null;

    if (ticket) {
      const decoded = verifyLoginTicket(ticket);
      if (!decoded) {
        return res.status(401).json({
          success: false,
          expired: true,
          error: "Sessão expirada. Volte para a tela de login e tente novamente."
        });
      }
      if (db.isSupabaseConfigured()) {
        try {
          member = await db.supabaseDb.findMember(decoded.username || decoded.id);
        } catch (e) {}
      }
      if (!member) {
        member = db.findMember(decoded.username || decoded.id);
      }
    } else if (username && password) {
      if (db.isSupabaseConfigured()) {
        try {
          member = await db.supabaseDb.findMember(username.trim());
        } catch (e) {}
      }
      if (!member) {
        member = db.findMember(username.trim());
      }
      if (!member || !db.verifyMemberPassword(member, password.trim())) {
        return res.status(401).json({
          success: false,
          error: "Credenciais inválidas."
        });
      }
    } else {
      return res.status(400).json({
        success: false,
        error: "Requisição inválida: ticket de autenticação ausente."
      });
    }

    if (!member) {
      return res.status(401).json({
        success: false,
        error: "Membro não encontrado."
      });
    }

    // 2. Rate limiting por IP e pelo membro
    const rateCheck = checkLoginRateLimit(ip, member.username);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        success: false,
        locked: true,
        error: rateCheck.error
      });
    }

    // 3. Validação do PIN numérico
    if (!pinEntered || !/^\d{4,8}$/.test(pinEntered)) {
      return res.status(400).json({
        success: false,
        error: "Informe um PIN numérico válido."
      });
    }

    const twoFactorValid = db.verifyMember2FA(member, pinEntered) || (typeof db.verifyMemberPin === 'function' && db.verifyMemberPin(member, pinEntered));

    if (!twoFactorValid) {
      recordLoginFailure(ip, member.username);
      db.recordLogin(member.username, ip, false, "LOGIN_PIN_INCORRETO", hwid || null);
      const attemptsLeft = getLoginAttemptsLeft(ip, member.username);

      if (attemptsLeft <= 0) {
        return res.status(429).json({
          success: false,
          locked: true,
          lockSeconds: 180,
          error: "Acesso bloqueado por segurança: Muitas tentativas incorretas."
        });
      }

      return res.status(401).json({
        success: false,
        attemptsLeft,
        error: `PIN incorreto. ${attemptsLeft} tentativa${attemptsLeft === 1 ? '' : 's'} restante${attemptsLeft === 1 ? '' : 's'}.`
      });
    }

    // 4. Verificação de IP Lock e HWID Lock
    const ipCheck = db.checkMemberIp(member, ip);
    if (!ipCheck.allowed) {
      db.recordLogin(member.username, ip, false, "LOGIN_IP_BLOQUEADO", hwid || null);
      return res.status(403).json({
        success: false,
        error: `🔒 IP Bloqueado: ${ipCheck.reason} Contate um administrador para liberar seu acesso.`,
        blocked: 'ip'
      });
    }

    if (hwid) {
      const hwidCheck = db.checkMemberHwid(member, hwid);
      if (!hwidCheck.allowed) {
        db.recordLogin(member.username, ip, false, "LOGIN_DISPOSITIVO_BLOQUEADO", hwid);
        return res.status(403).json({
          success: false,
          error: `🔒 Dispositivo Bloqueado: ${hwidCheck.reason} Contate um administrador para liberar seu acesso.`,
          blocked: 'hwid'
        });
      }
      if (hwidCheck.firstTime) {
        db.setTrustedHwid(member.username, hwid);
      }
    }

    if (ipCheck.firstTime) {
      db.setTrustedIp(member.username, ip);
    }

    // 5. Sucesso completo: limpa contadores de falhas e emite token JWT oficial
    clearLoginFailures(ip, member.username);
    db.recordLogin(member.username, ip, true, "LOGIN_PIN_SUCESSO", hwid || null);
    const token = generateMemberToken(member);

    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';
    res.cookie('nzi_token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: isHttps,
      path: '/'
    });

    return res.json({
      success: true,
      message: "PIN aceito. Acesso ao dashboard liberado.",
      token: token,
      redirectUrl: '/dashboard',
      member: {
        id: member.id,
        username: member.username,
        name: member.name,
        role: member.role,
        level: member.level,
        isAdmin: member.level <= 2,
        status: 'online',
        profitShare: member.profitShare,
        weeklyEarnings: member.weeklyEarnings
      }
    });
  } catch (err) {
    console.error('[auth/login/verify-pin]', err);
    return res.status(500).json({
      success: false,
      error: 'Erro interno ao validar PIN.',
      detail: String(err && err.message ? err.message : err)
    });
  }
}

app.post('/api/auth/login/step1', handleLoginStep1);
app.post('/api/auth/step1', handleLoginStep1);
app.post('/api/auth/login/verify-pin', handleVerifyPin);
app.post('/api/auth/verify-pin', handleVerifyPin);
app.post('/api/auth/step2', handleVerifyPin);

// Rota de Login: Acesso restrito a membros com autenticação de múltiplos fatores (Usuário, Senha e 2FA/OTP)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, pin, otp, code, hwid } = req.body || {};
    const ip = getClientIp(req);
    const twoFactorCode = (otp || pin || code || '').toString().trim();

    // 1. Verificação de rate limiting / proteção contra força bruta por IP e por Usuário
    const rateCheck = checkLoginRateLimit(ip, username);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        success: false,
        error: rateCheck.error
      });
    }

    // 2. Validação da presença dos campos obrigatórios
    if (!username || typeof username !== 'string' || !username.trim()) {
      return res.status(400).json({
        success: false,
        error: "Acesso restrito apenas para membros. Informe seu codinome de usuário."
      });
    }

    if (!password || typeof password !== 'string' || !password.trim()) {
      return res.status(400).json({
        success: false,
        error: "Acesso restrito apenas para membros. Informe sua senha de acesso."
      });
    }

    if (!twoFactorCode || !/^\d{6}$/.test(twoFactorCode)) {
      return res.status(400).json({
        success: false,
        error: "Autenticação 2FA obrigatória: Informe o código 2FA/OTP de 6 dígitos numéricos."
      });
    }

    // 3. Busca do membro na hierarquia (Supabase em tempo real ou banco local)
    let member = null;
    if (db.isSupabaseConfigured()) {
      try {
        member = await db.supabaseDb.findMember(username.trim());
      } catch (e) {}
    }
    if (!member) {
      member = db.findMember(username.trim());
    }

    if (!member) {
      recordLoginFailure(ip, username);
      db.recordLogin(username, ip, false, "LOGIN_FALHA_USUARIO", hwid || null);
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros. Credenciais inválidas (usuário, senha ou código 2FA/OTP incorretos)."
      });
    }

    // Se o membro foi bloqueado ou desativado
    if (member.status === 'bloqueado' || member.status === 'banido' || member.status === 'inativo') {
      db.recordLogin(member.username, ip, false, "LOGIN_STATUS_BLOQUEADO", hwid || null);
      return res.status(403).json({
        success: false,
        error: "🔒 Acesso bloqueado: Esta conta está suspensa na Nzi Mafia."
      });
    }

    // 4. Verificação segura da senha via bcrypt
    const passwordValid = db.verifyMemberPassword(member, password.trim());
    if (!passwordValid) {
      recordLoginFailure(ip, member.username);
      db.recordLogin(member.username, ip, false, "LOGIN_SENHA_INCORRETA", hwid || null);
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros. Credenciais inválidas (usuário, senha ou código 2FA/OTP incorretos)."
      });
    }

    // 5. Verificação de 2FA / OTP (TOTP RFC 6238 ou PIN de contingência)
    const twoFactorValid = db.verifyMember2FA(member, twoFactorCode);
    if (!twoFactorValid) {
      recordLoginFailure(ip, member.username);
      db.recordLogin(member.username, ip, false, "LOGIN_2FA_INCORRETO", hwid || null);
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros. Credenciais inválidas (usuário, senha ou código 2FA/OTP incorretos)."
      });
    }

    // 6. Verificação de IP confiável (IP Lock)
    const ipCheck = db.checkMemberIp(member, ip);
    if (!ipCheck.allowed) {
      db.recordLogin(member.username, ip, false, "LOGIN_IP_BLOQUEADO", hwid || null);
      return res.status(403).json({
        success: false,
        error: `🔒 IP Bloqueado: ${ipCheck.reason} Contate um administrador para liberar seu acesso.`,
        blocked: 'ip'
      });
    }

    // 7. Verificação de HWID confiável (Dispositivo Lock)
    if (hwid) {
      const hwidCheck = db.checkMemberHwid(member, hwid);
      if (!hwidCheck.allowed) {
        db.recordLogin(member.username, ip, false, "LOGIN_DISPOSITIVO_BLOQUEADO", hwid);
        return res.status(403).json({
          success: false,
          error: `🔒 Dispositivo Bloqueado: ${hwidCheck.reason} Contate um administrador para liberar seu acesso.`,
          blocked: 'hwid'
        });
      }
      if (hwidCheck.firstTime) {
        db.setTrustedHwid(member.username, hwid);
      }
    }

    if (ipCheck.firstTime) {
      db.setTrustedIp(member.username, ip);
    }

    // 8. Sucesso: Limpar falhas de IP/Usuário, registrar log de auditoria e emitir token JWT
    clearLoginFailures(ip, member.username);
    db.recordLogin(member.username, ip, true, "LOGIN_2FA_SUCESSO", hwid || null);
    const token = generateMemberToken(member);

    // Cookie de sessão seguro (HTTPS no Vercel / Cloudflare = secure)
    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';
    res.cookie('nzi_token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: isHttps,
      path: '/'
    });

    return res.json({
      success: true,
      message: "Autenticação 2FA realizada com sucesso. Acesso ao dashboard liberado.",
      token: token,
      redirectUrl: '/dashboard',
      member: {
        id: member.id,
        username: member.username,
        name: member.name,
        role: member.role,
        level: member.level,
        isAdmin: member.level <= 2,
        status: 'online',
        profitShare: member.profitShare,
        weeklyEarnings: member.weeklyEarnings
      }
    });
  } catch (err) {
    console.error('[auth/login]', err);
    return res.status(500).json({
      success: false,
      error: 'Erro interno no login. Tente novamente.',
      detail: String(err && err.message ? err.message : err)
    });
  }
});

// Logout seguro do membro
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('nzi_token');
  res.json({
    success: true,
    message: "Sessão finalizada com sucesso. Login encerrado."
  });
});

// Status atual de autenticação (sem forçar redirect de visitante)
app.get('/api/auth/current', optionalMemberAuth, (req, res) => {
  if (req.member) {
    return res.json({
      success: true,
      authenticated: true,
      member: req.member,
      isAdmin: Boolean(req.member.isAdmin)
    });
  }
  res.json({
    success: true,
    authenticated: false,
    member: null,
    isAdmin: false
  });
});

// Perfil do membro logado
app.get('/api/auth/me', requireMemberAuth, (req, res) => {
  const member = db.findMember(req.member.id);
  res.json({
    success: true,
    member: {
      id: member.id,
      username: member.username,
      name: member.name,
      role: member.role,
      level: member.level,
      isAdmin: member.level <= 2,
      status: member.status,
      lastLogin: member.lastLogin,
      profitShare: member.profitShare,
      weeklyEarnings: member.weeklyEarnings,
      avatarUrl: member.avatarUrl || null
    }
  });
});

// Cadastro de novo Administrador / Membro (Exclusivo para Dono Nível 1 ou Setup Inicial Protegido)
app.post('/api/auth/register-admin', (req, res, next) => {
  const database = db.getDb();
  const hasOwner = Array.isArray(database.members) && database.members.some(m => m.level === 1);

  if (hasOwner) {
    // Se a organização já possui Dono, exige autenticação do Owner Nível 1
    return requireAdminAuth(req, res, () => {
      requireMinLevel(1)(req, res, next);
    });
  }

  // Setup inicial: exige chave secreta de ambiente ADMIN_SETUP_SECRET
  const setupKey = req.headers['x-setup-key'] || req.body.setupKey;
  const expected = process.env.ADMIN_SETUP_SECRET;
  if (!expected || expected.length < 16 || setupKey !== expected) {
    return res.status(403).json({
      success: false,
      error: "Acesso negado: O setup inicial de administrador exige a chave ADMIN_SETUP_SECRET configurada no servidor (mínimo 16 caracteres)."
    });
  }
  next();
}, (req, res) => {
  const { username, name, password, pin, role, level } = req.body;
  if (!validatePassword(password)) {
    return res.status(400).json({
      success: false,
      error: "Senha inválida: deve conter no mínimo 8 caracteres."
    });
  }
  if (!validatePinFormat(pin)) {
    return res.status(400).json({
      success: false,
      error: "PIN inválido: deve conter exatamente 6 dígitos numéricos."
    });
  }
  try {
    const member = db.addMember({
      username,
      name,
      role: role || "Founder",
      level: Number(level) || 2,
      password,
      pin
    });
    res.status(201).json({
      success: true,
      message: `Administrador '${member.name}' cadastrado com sucesso com 2FA!`,
      member: {
        id: member.id,
        username: member.username,
        name: member.name,
        role: member.role,
        level: member.level,
        isAdmin: member.level <= 2
      }
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Troca de Senha pelo próprio membro autenticado
app.post('/api/auth/change-password', requireMemberAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const ip = getClientIp(req);

  const rate = checkActionRateLimit(`passchange:${req.member.id}`, 5, 300000, "alteração de senha");
  if (!rate.allowed) {
    return res.status(429).json({ success: false, error: rate.error });
  }

  if (!validatePassword(newPassword)) {
    return res.status(400).json({
      success: false,
      error: "A nova senha deve conter pelo menos 8 caracteres."
    });
  }

  const member = db.findMember(req.member.id);
  if (!db.verifyMemberPassword(member, currentPassword)) {
    recordActionFailure(`passchange:${req.member.id}`);
    recordLoginFailure(ip, req.member.username);
    db.recordLogin(req.member.username, ip, false, "CHANGE_PASSWORD_INCORRETO", null);
    return res.status(401).json({
      success: false,
      error: "A senha atual informada está incorreta."
    });
  }

  clearActionFailures(`passchange:${req.member.id}`);

  try {
    const updated = db.updateMemberPassword(member.username, newPassword);
    const newToken = generateMemberToken(updated);
    res.cookie('nzi_token', newToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.VERCEL === '1'
    });

    db.recordLogin(member.username, ip, true, "SENHA_ALTERADA_SUCESSO", null);
    return res.json({
      success: true,
      message: "Senha alterada com sucesso! Suas outras sessões foram invalidadas por segurança.",
      token: newToken
    });
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

// Troca de PIN de 6 dígitos pelo próprio membro no dashboard
app.post('/api/auth/change-pin', requireMemberAuth, (req, res) => {
  const { currentPin, newPin } = req.body;
  const ip = getClientIp(req);

  const rate = checkActionRateLimit(`pinchange:${req.member.id}`, 5, 300000, "alteração de PIN");
  if (!rate.allowed) {
    return res.status(429).json({ success: false, error: rate.error });
  }

  if (!validatePinFormat(currentPin)) {
    return res.status(400).json({
      success: false,
      error: "Acesso restrito apenas para membros: O PIN atual deve conter 6 dígitos numéricos."
    });
  }

  if (!validatePinFormat(newPin)) {
    return res.status(400).json({
      success: false,
      error: "Acesso restrito apenas para membros: O novo PIN deve conter exatamente 6 dígitos numéricos."
    });
  }

  const member = db.findMember(req.member.id);
  if (!db.verifyMemberPin(member, currentPin.toString().trim())) {
    recordActionFailure(`pinchange:${req.member.id}`);
    recordLoginFailure(ip, req.member.username);
    db.recordLogin(req.member.username, ip, false, "CHANGE_PIN_INCORRETO", null);
    return res.status(401).json({
      success: false,
      error: "Acesso restrito apenas para membros: O PIN atual informado está incorreto."
    });
  }

  clearActionFailures(`pinchange:${req.member.id}`);

  try {
    const updated = db.updateMemberPin(member.username, newPin.toString().trim());
    const newToken = generateMemberToken(updated);
    res.cookie('nzi_token', newToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });

    db.recordLogin(member.username, ip, true, "PIN_ALTERADO_SUCESSO", null);

    return res.json({
      success: true,
      message: "PIN de 6 dígitos alterado com sucesso! Suas outras sessões foram invalidadas por segurança.",
      token: newToken
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err.message
    });
  }
});

// ==========================================
// ROTAS DO BACK-END DO DASHBOARD (ACESSO RESTRITO APENAS PARA MEMBROS)
// ==========================================

// Visão Geral / Dados Financeiros e Métricas do Membro
app.get('/api/dashboard/overview', requireMemberAuth, (req, res) => {
  const database = db.getDb();
  const currentMember = database.members.find(m => m.id === req.member.id) || req.member;

  res.json({
    success: true,
    financials: database.financials,
    memberStats: {
      role: currentMember.role,
      level: currentMember.level,
      profitShare: currentMember.profitShare,
      weeklyEarnings: currentMember.weeklyEarnings
    },
    operationsCount: database.operations.length,
    activeMembersCount: database.members.filter(m => m.status === 'online').length,
    totalMembers: database.members.length
  });
});

// Lista de Membros da Nzi Mafia com status e hierarquia em tempo real
app.get('/api/dashboard/members', requireMemberAuth, (req, res) => {
  const database = db.getDb();
  const members = database.members.map(m => ({
    id: m.id,
    username: m.username,
    name: m.name,
    role: m.role,
    level: m.level,
    status: m.status,
    profitShare: m.profitShare,
    weeklyEarnings: m.weeklyEarnings,
    lastLogin: m.lastLogin,
    avatarUrl: m.avatarUrl || null
  }));
  res.json({ success: true, members });
});

// Atualizar ícone/avatar (hospedado no Imgur) de um membro
app.post('/api/members/:id/avatar', requireMemberAuth, (req, res) => {
  const targetId = req.params.id;
  const { avatarUrl } = req.body;
  const isSelf = (req.member.id === targetId || req.member.username.toLowerCase() === String(targetId).toLowerCase());

  // Donos/Fundadores podem atualizar de qualquer um; membros comuns podem atualizar o seu próprio
  if (!req.member.isAdmin && !isSelf) {
    return res.status(403).json({
      success: false,
      error: "Você só pode alterar o ícone do seu próprio perfil."
    });
  }

  try {
    const updated = db.updateMemberAvatar(targetId, avatarUrl);
    res.json({
      success: true,
      message: `Ícone de @${updated.username} atualizado com sucesso!`,
      avatarUrl: updated.avatarUrl,
      member: {
        id: updated.id,
        username: updated.username,
        name: updated.name,
        avatarUrl: updated.avatarUrl
      }
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Atualizar o próprio status em tempo real (Ex: 'online', 'em missão', 'em operação', 'ocupado')
app.post('/api/dashboard/my-status', requireMemberAuth, (req, res) => {
  const { status } = req.body;
  const validStatuses = ['online', 'em missão', 'em operação', 'ocupado', 'offline'];
  const newStatus = status ? status.toLowerCase().trim() : 'online';

  if (!validStatuses.includes(newStatus)) {
    return res.status(400).json({
      success: false,
      error: "Status inválido. Escolha entre: online, em missão, em operação, ocupado, offline."
    });
  }

  const updated = db.updateMemberStatus(req.member.id, newStatus);
  res.json({
    success: true,
    message: `Status atualizado para: ${newStatus.toUpperCase()}`,
    status: newStatus,
    member: updated
  });
});

// Mural Confidencial da Nzi Mafia
app.get('/api/dashboard/announcements', requireMemberAuth, (req, res) => {
  const database = db.getDb();
  res.json({ success: true, announcements: database.announcements });
});

// Publicar Novo Comunicado Confidencial (Apenas hierarquias 1, 2 e 3: Owner, Founder, Posses)
app.post('/api/dashboard/announcements', requireMemberAuth, requireMinLevel(3), (req, res) => {
  const { title, content, pinned } = req.body;
  if (!title || !content) {
    return res.status(400).json({
      success: false,
      error: "Título e conteúdo do comunicado são obrigatórios."
    });
  }

  const newAnn = db.addAnnouncement({
    author: req.member.name,
    role: req.member.role,
    title: title.trim(),
    content: content.trim(),
    pinned: Boolean(pinned)
  });

  res.status(201).json({
    success: true,
    message: "Comunicado confidencial publicado com sucesso.",
    announcement: newAnn
  });
});

// Livro de Caixa e Transações Financeiras do Cofre
app.get('/api/dashboard/transactions', requireMemberAuth, (req, res) => {
  const database = db.getDb();
  res.json({
    success: true,
    totalVault: database.financials.totalVault,
    weeklyProfit: database.financials.weeklyProfit,
    transactions: database.transactions
  });
});

// Lançar Nova Movimentação Financeira no Cofre (Apenas Dono e Fundador - Níveis 1 e 2)
app.post('/api/dashboard/transactions', requireMemberAuth, requireMinLevel(2), (req, res) => {
  const { type, amount, description, pin } = req.body;
  const ip = getClientIp(req);

  // Confirmação de PIN (6 dígitos) com rate limiting para ações sensíveis no cofre
  const rate = checkActionRateLimit(`vault:${req.member.id}`, 5, 120000, "movimentação no cofre");
  if (!rate.allowed) {
    return res.status(429).json({ success: false, error: rate.error });
  }

  if (!validatePinFormat(pin)) {
    return res.status(400).json({
      success: false,
      error: "Acesso restrito apenas para membros: confirme sua ação com o PIN de 6 dígitos numéricos."
    });
  }

  const currentMember = db.findMember(req.member.id);
  if (!db.verifyMemberPin(currentMember, pin.toString().trim())) {
    recordActionFailure(`vault:${req.member.id}`);
    recordLoginFailure(ip, req.member.username);
    db.recordLogin(req.member.username, ip, false, "TRANSACTION_PIN_INCORRETO", null);
    return res.status(403).json({
      success: false,
      error: "Acesso restrito apenas para membros. PIN de 6 dígitos incorreto."
    });
  }
  clearActionFailures(`vault:${req.member.id}`);

  if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
    return res.status(400).json({
      success: false,
      error: "Valor da transação inválido. Deve ser um número positivo."
    });
  }

  try {
    const tx = db.addTransaction({
      type: type === 'OUT' ? 'OUT' : 'IN',
      amount: Number(amount),
      description: description ? String(description).slice(0, 255) : "Movimentação interna no cofre",
      author: req.member.name
    });

    res.status(201).json({
      success: true,
      message: "Movimentação registrada com sucesso no cofre da Nzi Mafia.",
      transaction: tx,
      newTotalVault: db.getDb().financials.totalVault
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Operações da Nzi Mafia
app.get('/api/dashboard/operations', requireMemberAuth, (req, res) => {
  const database = db.getDb();
  res.json({ success: true, operations: database.operations });
});

// Criar Nova Operação (Apenas liderança: Níveis 1, 2 e 3)
app.post('/api/dashboard/operations', requireMemberAuth, requireMinLevel(3), (req, res) => {
  const { title, target, leader, priority, description } = req.body;
  if (!title) {
    return res.status(400).json({
      success: false,
      error: "Título da operação é obrigatório."
    });
  }

  const op = db.addOperation({
    title,
    target,
    leader: leader || req.member.name,
    priority: priority || "ALTA",
    description
  });

  res.status(201).json({
    success: true,
    message: "Nova operação iniciada com sucesso.",
    operation: op
  });
});

// Atualizar Status ou Dados de uma Operação (Apenas liderança: Níveis 1, 2 e 3)
app.patch('/api/dashboard/operations/:id', requireMemberAuth, requireMinLevel(3), (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    const updated = db.updateOperation(id, updates);
    res.json({
      success: true,
      message: "Operação atualizada com sucesso.",
      operation: updated
    });
  } catch (err) {
    res.status(404).json({
      success: false,
      error: err.message
    });
  }
});

// Logs de Auditoria (Registro de logins com PIN de 6 dígitos, IP, data e status)
app.get('/api/dashboard/audit-logs', requireMemberAuth, (req, res) => {
  const database = db.getDb();
  res.json({ success: true, auditLogs: database.auditLogs });
});

// ==========================================
// ROTAS PÚBLICAS DO DASHBOARD & CONTEÚDOS
// ==========================================

// Estatísticas reais do dashboard (contagem de posts por categoria, eventos ativos/confirmados, últimas publicações)
app.get('/api/public/stats', (req, res) => {
  try {
    const stats = db.getDashboardStats();
    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Publicações Públicas (filtradas por categoria, busca, apenas com status Publicado)
app.get('/api/public/posts', (req, res) => {
  try {
    const { category, search } = req.query;
    const posts = db.getPosts({ category, search, includeUnpublished: false });
    res.json({ success: true, posts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Detalhes de uma publicação pública
app.get('/api/public/posts/:id', (req, res) => {
  const post = db.getPostById(req.params.id);
  if (!post || post.status !== 'Publicado') {
    return res.status(404).json({ success: false, error: "Publicação não encontrada ou indisponível." });
  }
  res.json({ success: true, post });
});

// Eventos Públicos (com data/hora reais, temporizador regressivo e status)
app.get('/api/public/events', (req, res) => {
  try {
    const { status, search } = req.query;
    const events = db.getEvents({ status, search, includeUnpublished: false });
    res.json({ success: true, events });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Detalhes de um evento público
app.get('/api/public/events/:id', (req, res) => {
  const event = db.getEventById(req.params.id);
  if (!event || event.published === false) {
    return res.status(404).json({ success: false, error: "Evento não encontrado ou indisponível." });
  }
  res.json({ success: true, event });
});

// Central de Links (4 aplicativos: Root, Discord, Telegram, TikTok)
app.get('/api/public/links', (req, res) => {
  try {
    const links = db.getLinks();
    res.json({ success: true, links });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Contas Discord Públicas e Rewards (filtra contas já reivindicadas, mantendo visível apenas para o membro que reivindicou)
app.get('/api/public/discord', optionalMemberAuth, (req, res) => {
  try {
    const accounts = db.getDiscordAccounts(false, req.member || null);
    res.json({ success: true, accounts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==========================================
// ROTAS DE ADMINISTRAÇÃO E OPERAÇÕES (PROTEGIDAS)
// Exclusivo para administradores autenticados (Dono e Fundador)
// ==========================================

// Listar todas as publicações (incluindo rascunhos e despublicadas)
app.get('/api/admin/posts', requireAdminAuth, (req, res) => {
  try {
    const { category, status, search } = req.query;
    const posts = db.getPosts({ category, status, search, includeUnpublished: true });
    res.json({ success: true, posts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Criar nova publicação
app.post('/api/admin/posts', requireAdminAuth, (req, res) => {
  try {
    const { title, description, category, image, link, status } = req.body;
    if (!title || typeof title !== 'string' || !title.trim()) {
      return res.status(400).json({ success: false, error: "Título da publicação é obrigatório." });
    }
    const safeImage = sanitizeUrl(image);
    const safeLink = sanitizeUrl(link);
    const post = db.addPost({
      title: title.trim().slice(0, 200),
      description: description ? String(description).slice(0, 10000) : '',
      category: category ? String(category).slice(0, 50) : 'Geral',
      image: safeImage,
      link: safeLink,
      status,
      author: req.member.name
    });
    res.status(201).json({
      success: true,
      message: `Publicação criada com sucesso na categoria ${post.category}!`,
      post
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Atualizar publicação existente
app.put('/api/admin/posts/:id', requireAdminAuth, (req, res) => {
  try {
    const updates = { ...req.body };
    if (updates.title) updates.title = String(updates.title).trim().slice(0, 200);
    if (updates.image !== undefined) updates.image = sanitizeUrl(updates.image);
    if (updates.link !== undefined) updates.link = sanitizeUrl(updates.link);
    const post = db.updatePost(req.params.id, updates);
    res.json({
      success: true,
      message: "Publicação atualizada com sucesso no banco de dados!",
      post
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Publicar / Despublicar publicação
app.patch('/api/admin/posts/:id/publish', requireAdminAuth, (req, res) => {
  try {
    const post = db.togglePublishPost(req.params.id);
    const msg = post.status === 'Publicado' 
      ? "Publicação publicada com sucesso e visível no dashboard!" 
      : "Publicação despublicada com sucesso.";
    res.json({ success: true, message: msg, post });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Excluir publicação
app.delete('/api/admin/posts/:id', requireAdminAuth, (req, res) => {
  try {
    db.deletePost(req.params.id);
    res.json({ success: true, message: "Publicação excluída com sucesso do sistema!" });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// --- Gerenciamento de Eventos ---

// Listar todos os eventos
app.get('/api/admin/events', requireAdminAuth, (req, res) => {
  try {
    const { status, search } = req.query;
    const events = db.getEvents({ status, search, includeUnpublished: true });
    res.json({ success: true, events });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Criar evento
app.post('/api/admin/events', requireAdminAuth, (req, res) => {
  try {
    const { title, description, eventDate, timezone, startTime, endTime, status, published } = req.body;
    const event = db.addEvent({
      title,
      description,
      eventDate,
      timezone,
      startTime,
      endTime,
      status,
      published
    });
    res.status(201).json({
      success: true,
      message: `Evento '${event.title}' agendado com sucesso!`,
      event
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Atualizar evento
app.put('/api/admin/events/:id', requireAdminAuth, (req, res) => {
  try {
    const event = db.updateEvent(req.params.id, req.body);
    res.json({
      success: true,
      message: `Evento '${event.title}' atualizado com sucesso!`,
      event
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Alterar status do evento
app.patch('/api/admin/events/:id/status', requireAdminAuth, (req, res) => {
  try {
    const { status } = req.body;
    const event = db.updateEvent(req.params.id, { status });
    res.json({
      success: true,
      message: `Status do evento alterado para '${status}'!`,
      event
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Publicar / Despublicar evento
app.patch('/api/admin/events/:id/publish', requireAdminAuth, (req, res) => {
  try {
    const event = db.togglePublishEvent(req.params.id);
    const msg = event.published ? "Evento publicado com sucesso!" : "Evento despublicado com sucesso.";
    res.json({ success: true, message: msg, event });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Excluir evento
app.delete('/api/admin/events/:id', requireAdminAuth, (req, res) => {
  try {
    db.deleteEvent(req.params.id);
    res.json({ success: true, message: "Evento excluído com sucesso!" });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// --- Gerenciamento da Central de Links ---

// Listar links para admin
app.get('/api/admin/links', requireAdminAuth, (req, res) => {
  try {
    const links = db.getLinks();
    res.json({ success: true, links });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Atualizar URL de um aplicativo da Central de Links
app.put('/api/admin/links/:appKey', requireAdminAuth, (req, res) => {
  try {
    const { url, description, name } = req.body;
    const safeUrl = sanitizeUrl(url);
    if (url && !safeUrl) {
      return res.status(400).json({
        success: false,
        error: "URL inválida ou insegura. O link deve iniciar com https://, http:// ou /"
      });
    }
    const updated = db.updateLink(req.params.appKey, { url: safeUrl, description, name });
    res.json({
      success: true,
      message: `Link do aplicativo '${updated.name}' configurado com sucesso!`,
      link: updated
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// --- Gerenciamento de Contas Discord & Cofre de Credenciais ---

// Listar contas para admin
app.get('/api/admin/discord', requireAdminAuth, (req, res) => {
  try {
    const accounts = db.getDiscordAccounts(true, req.member);
    res.json({ success: true, accounts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Cadastrar conta Discord (somente Owner Nível 1)
app.post('/api/admin/discord', requireAdminAuth, requireMinLevel(1), (req, res) => {
  try {
    const { title, email, senha, token, description, status, isPublicDisclosed, isReward } = req.body;
    const account = db.addDiscordAccount({
      title,
      email,
      senha,
      token,
      description,
      status,
      isPublicDisclosed,
      isReward
    });
    res.status(201).json({
      success: true,
      message: `Conta Discord '${account.title}' cadastrada com armazenamento seguro (AES-256)!`,
      account
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Atualizar conta Discord
app.put('/api/admin/discord/:id', requireAdminAuth, (req, res) => {
  try {
    const updated = db.updateDiscordAccount(req.params.id, req.body);
    res.json({
      success: true,
      message: "Configurações da conta Discord atualizadas com sucesso!",
      account: updated
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Excluir conta Discord
app.delete('/api/admin/discord/:id', requireAdminAuth, (req, res) => {
  try {
    db.deleteDiscordAccount(req.params.id);
    res.json({ success: true, message: "Conta Discord removida com sucesso!" });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Revelar credencial sensível de conta Discord (com confirmação de PIN e registro de auditoria)
app.post('/api/admin/discord/:id/reveal', requireAdminAuth, (req, res) => {
  const { pin } = req.body;
  const ip = getClientIp(req);

  const rate = checkActionRateLimit(`reveal:${req.member.id}`, 5, 120000, "consulta de credencial Discord");
  if (!rate.allowed) {
    return res.status(429).json({ success: false, error: rate.error });
  }

  if (!validatePinFormat(pin)) {
    return res.status(400).json({
      success: false,
      error: "Confirmação obrigatória: informe seu PIN de 6 dígitos numéricos para liberar a visualização."
    });
  }

  const currentAdmin = db.findMember(req.member.id);
  if (!db.verifyMemberPin(currentAdmin, pin.toString().trim())) {
    recordActionFailure(`reveal:${req.member.id}`);
    recordLoginFailure(ip, req.member.username);
    db.recordLogin(req.member.username, ip, false, `REVEAL_FALHA_PIN_DISCORD: ${req.params.id}`, null);
    return res.status(403).json({
      success: false,
      error: "PIN incorreto. Tentativa de acesso a credencial registrada na auditoria de segurança."
    });
  }

  clearActionFailures(`reveal:${req.member.id}`);

  try {
    const result = db.revealDiscordSecret(req.params.id, req.member, ip);
    res.json({
      success: true,
      message: "Credencial decodificada com sucesso. Ação registrada no livro de auditoria.",
      secret: result.secret,
      title: result.title
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// ==========================================
// SISTEMA DE REWARD / RESGATE DE CONTAS DISCORD
// ==========================================

// Reivindicar / Resgatar Conta Discord (Apenas para membros autenticados)
// Ao reivindicar, a conta some do dashboard para todos os outros membros
app.post('/api/discord/:id/claim', requireMemberAuth, (req, res) => {
  try {
    const ip = getClientIp(req);
    const result = db.claimDiscordAccount(req.params.id, req.member, ip);
    res.json(result);
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Consultar credenciais da conta reivindicada (exclusivo para quem reivindicou ou Admin)
app.get('/api/discord/:id/my-credentials', requireMemberAuth, (req, res) => {
  try {
    const data = db.getClaimedCredentials(req.params.id, req.member);
    res.json({ success: true, account: data });
  } catch (err) {
    res.status(403).json({ success: false, error: err.message });
  }
});

// Resetar status de reivindicação de uma conta Discord (somente Admin)
app.post('/api/admin/discord/:id/reset-claim', requireAdminAuth, (req, res) => {
  try {
    const ip = getClientIp(req);
    const result = db.resetDiscordClaim(req.params.id, req.member, ip);
    res.json(result);
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});


// ==========================================
// ROTAS PAINEL (user, senha, tipo_login) — somente Owner Nível 1
// ==========================================
app.get('/api/admin/painel', requireAdminAuth, (req, res) => {
  try {
    res.json({ success: true, accounts: db.getPanelAccounts(true) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/public/painel', (req, res) => {
  try {
    res.json({ success: true, accounts: db.getPanelAccounts(false) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/painel', requireAdminAuth, requireMinLevel(1), (req, res) => {
  try {
    const account = db.addPanelAccount(req.body);
    res.status(201).json({ success: true, message: 'Painel cadastrado com criptografia AES-256!', account });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.put('/api/admin/painel/:id', requireAdminAuth, requireMinLevel(1), (req, res) => {
  try {
    const account = db.updatePanelAccount(req.params.id, req.body);
    res.json({ success: true, message: 'Painel atualizado!', account });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.delete('/api/admin/painel/:id', requireAdminAuth, requireMinLevel(1), (req, res) => {
  try {
    db.deletePanelAccount(req.params.id);
    res.json({ success: true, message: 'Painel removido!' });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/painel/:id/reveal', requireAdminAuth, (req, res) => {
  const { pin } = req.body;
  const ip = getClientIp(req);

  const rate = checkActionRateLimit(`reveal:${req.member.id}`, 5, 120000, "consulta de credencial Painel");
  if (!rate.allowed) {
    return res.status(429).json({ success: false, error: rate.error });
  }

  if (!validatePinFormat(pin)) {
    return res.status(400).json({ success: false, error: 'Informe seu PIN de 6 dígitos para visualizar.' });
  }

  const currentAdmin = db.findMember(req.member.id);
  if (!db.verifyMemberPin(currentAdmin, pin.toString().trim())) {
    recordActionFailure(`reveal:${req.member.id}`);
    recordLoginFailure(ip, req.member.username);
    db.recordLogin(req.member.username, ip, false, `REVEAL_FALHA_PIN_PAINEL: ${req.params.id}`, null);
    return res.status(403).json({ success: false, error: 'PIN incorreto. Tentativa registrada na auditoria.' });
  }

  clearActionFailures(`reveal:${req.member.id}`);

  try {
    const result = db.revealPanelSecret(req.params.id, req.member, ip);
    res.json({ success: true, message: 'Credenciais decodificadas. Ação auditada.', secret: result.secret, label: result.label, user: result.user, tipoLogin: result.tipoLogin });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Cadastro de novos membros por administradores
app.post('/api/admin/users', requireAdminAuth, (req, res) => {
  try {
    const { username, name, role, level, pin, password } = req.body;
    if (pin && !validatePinFormat(pin)) {
      return res.status(400).json({
        success: false,
        error: "O PIN do novo membro deve conter exatamente 6 dígitos numéricos."
      });
    }
    if (password && !validatePassword(password)) {
      return res.status(400).json({
        success: false,
        error: "A senha deve conter no mínimo 8 caracteres."
      });
    }
    const memberLevel = Number(level);
    if (!memberLevel || memberLevel < 1 || memberLevel > 5) {
      return res.status(400).json({
        success: false,
        error: "Nível hierárquico inválido. Deve ser entre 1 e 5."
      });
    }
    const member = db.addMember({
      username: String(username).trim().toLowerCase(),
      name: String(name).trim(),
      role: role ? String(role).trim() : 'Member',
      level: memberLevel,
      pin,
      password
    });
    res.status(201).json({
      success: true,
      message: `Integrante '${member.name}' cadastrado na organização com sucesso com 2FA!`,
      member: {
        id: member.id,
        username: member.username,
        name: member.name,
        role: member.role,
        level: member.level
      }
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// ==========================================
// ROTAS DE SEGURANÇA: IP LOCK & HWID LOCK (ADMIN)
// ==========================================

// Listar status de segurança (IP e HWID) de todos os membros
app.get('/api/admin/security', requireAdminAuth, (req, res) => {
  try {
    const database = db.getDb();
    const securityInfo = database.members.map(m => ({
      id: m.id,
      username: m.username,
      name: m.name,
      role: m.role,
      trustedIp: m.trustedIp || null,
      trustedHwid: m.trustedHwid ? m.trustedHwid.substring(0, 16) + '...' : null,
      hwidFull: m.trustedHwid || null,
      lastLogin: m.lastLogin || null
    }));
    res.json({ success: true, members: securityInfo });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Resetar IP e HWID de um membro (libera o próximo login de qualquer lugar)
app.post('/api/admin/security/:username/reset', requireAdminAuth, (req, res) => {
  try {
    const member = db.resetMemberSecurity(req.params.username);
    const ip = getClientIp(req);
    db.recordLogin(req.params.username, ip, true, `RESET_SEGURANCA_ADMIN_por_${req.member.name}`, null);
    res.json({
      success: true,
      message: `✅ IP e HWID de '${member.name}' resetados. Próximo login liberado de qualquer dispositivo/IP.`,
      member: { id: member.id, username: member.username, name: member.name }
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Resetar apenas o IP de um membro
app.post('/api/admin/security/:username/reset-ip', requireAdminAuth, (req, res) => {
  try {
    const m = db.setTrustedIp(req.params.username, null);
    const ip = getClientIp(req);
    db.recordLogin(req.params.username, ip, true, `RESET_IP_ADMIN_por_${req.member.name}`, null);
    res.json({
      success: true,
      message: `✅ IP de '${m.name}' resetado. Próximo login registrará novo IP confiável.`
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Resetar apenas o HWID de um membro
app.post('/api/admin/security/:username/reset-hwid', requireAdminAuth, (req, res) => {
  try {
    const m = db.setTrustedHwid(req.params.username, null);
    const ip = getClientIp(req);
    db.recordLogin(req.params.username, ip, true, `RESET_HWID_ADMIN_por_${req.member.name}`, null);
    res.json({
      success: true,
      message: `✅ HWID de '${m.name}' resetado. Próximo login registrará novo dispositivo confiável.`
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// ==========================================
// RASTREAMENTO DE ACESSOS (estatísticas por IP, localização aproximada, LGPD)
// ==========================================
require('./tracking-server').mount(app, { requireAdminAuth });

// ==========================================
// RECRUTAMENTO (candidaturas para a tag da NZI)
// ==========================================
require('./recruitment-server').mount(app, { requireAdminAuth });

// Erros não tratados nas rotas (evita HTML genérico 500 no Vercel)
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  if (res.headersSent) return next(err);
  res.status(500).json({
    success: false,
    error: 'Erro interno do servidor.',
    detail: String(err && err.message ? err.message : err)
  });
});

// Middleware Global de Tratamento de 404
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      error: "Endpoint não encontrado na API da Nzi Mafia."
    });
  }
  res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// Iniciar servidor apenas se executado diretamente
if (require.main === module) {
  app.listen(PORT, async () => {
    console.log(`=======================================================`);
    console.log(`[NZI MAFIA] Servidor Back-end Online na porta ${PORT}`);
    console.log(`[SEGURANÇA] ACESSO RESTRITO APENAS PARA MEMBROS`);
    console.log(`[AUTENTICAÇÃO] PIN de 6 Dígitos ativado no login`);
    console.log(`[URL] http://localhost:${PORT}`);
    console.log(`[LOGIN] http://localhost:${PORT}/login`);
    console.log(`[DASHBOARD] http://localhost:${PORT}/dashboard`);
    console.log(`[ENTRETENIMENTO] http://localhost:${PORT}/entretenimento`);

    if (db.isSupabaseConfigured()) {
      const supCheck = await db.testSupabaseConnection();
      if (supCheck.connected) {
        console.log(`[BANCO SUPABASE] ✅ CONECTADO e SINCRONIZADO`);
      } else {
        console.log(`[BANCO SUPABASE] ⚠️ Configurado, mas aguardando schema: ${supCheck.error || supCheck.message}`);
      }
    } else {
      console.log(`[BANCO SUPABASE] ℹ️ Modo Local Ativo (data/database.json)`);
      console.log(`[BANCO SUPABASE] Para ativar nuvem: preencha o arquivo .env`);
    }
    console.log(`=======================================================`);
  });
}

module.exports = app;
