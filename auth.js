const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const db = require('./db');

// Configuração segura do JWT_SECRET:
// Se não houver JWT_SECRET no ambiente, geramos uma chave criptográfica forte em memória
// para impedir que invasores usem o segredo padrão previamente vazado.
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'nzi_mafia_vault_token_777_dinheiro_primeiro_super_secure') {
  try {
    const envFile = path.resolve(__dirname, '.env');
    if (fs.existsSync(envFile)) {
      const match = fs.readFileSync(envFile, 'utf8').match(/JWT_SECRET=([^\r\n]+)/);
      if (match && match[1]) JWT_SECRET = match[1].trim();
    }
  } catch (e) {}
}
if (!JWT_SECRET || JWT_SECRET === 'nzi_mafia_vault_token_777_dinheiro_primeiro_super_secure') {
  const secretFile = path.resolve(__dirname, 'data/.vault_key');
  try {
    if (fs.existsSync(secretFile)) {
      JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
    }
  } catch (e) {}

  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    try {
      const dataDir = path.dirname(secretFile);
      if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
      fs.writeFileSync(secretFile, JWT_SECRET, 'utf8');
    } catch (e) {}
  }
}
const TOKEN_EXPIRY = '24h';

// ==========================================
// VALIDAÇÃO DE FORMATOS DE CREDENCIAIS
// ==========================================

// Validação estrita de PIN numérico de 6 dígitos
function validatePinFormat(pin) {
  if (typeof pin !== 'string' && typeof pin !== 'number') return false;
  const pinStr = pin.toString().trim();
  return /^\d{6}$/.test(pinStr);
}

// Validação de senha forte (mínimo 8 caracteres)
function validatePassword(password) {
  if (typeof password !== 'string') return false;
  const pass = password.trim();
  return pass.length >= 8;
}

// ==========================================
// DETECÇÃO DE IP REAL (CLOUDFLARE + VERCEL + PROXY)
// ==========================================
function getClientIp(req) {
  if (!req) return '127.0.0.1';
  
  // 1. Cloudflare Edge: CF-Connecting-IP é o cabeçalho mais confiável quando a Cloudflare está ativa
  const cfIp = req.headers && (req.headers['cf-connecting-ip'] || req.headers['true-client-ip']);
  if (cfIp && typeof cfIp === 'string') {
    const clean = cfIp.split(',')[0].trim().replace(/^::ffff:/i, '');
    if (clean) return clean;
  }

  // 2. Vercel & Proxies reversos confiáveis
  if (req.app && req.app.get('trust proxy')) {
    const xff = req.headers && (req.headers['x-forwarded-for'] || req.headers['x-vercel-forwarded-for']);
    if (xff && typeof xff === 'string') {
      const clean = xff.split(',')[0].trim().replace(/^::ffff:/i, '');
      if (clean) return clean;
    }
    if (req.ip) return req.ip.replace(/^::ffff:/i, '').trim();
  }

  // 3. Conexão direta de socket
  const direct = (req.socket && req.socket.remoteAddress) || req.ip || '127.0.0.1';
  return direct.replace(/^::ffff:/i, '').trim();
}

// ==========================================
// 2FA / TOTP (RFC 6238 - ZERO DEPENDÊNCIAS EXTERNAS)
// ==========================================

// Alfabeto RFC 4648 Base32
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(base32) {
  const clean = String(base32 || '').toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const output = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

// Gera novo segredo Base32 para TOTP (160 bits / 20 bytes recomendado pelo RFC 6238)
function generateTotpSecret() {
  const buf = crypto.randomBytes(20);
  return base32Encode(buf);
}

// Gera código TOTP de 6 dígitos para o instante de tempo (RFC 6238 HMAC-SHA1)
function generateTOTP(secret, timeStep = 30, forTime = Date.now()) {
  if (!secret) return '';
  const counter = Math.floor(forTime / 1000 / timeStep);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));

  const cleanSecret = String(secret).replace(/\s+/g, '');
  const key = /^[A-Z2-7=]+$/i.test(cleanSecret)
    ? base32Decode(cleanSecret)
    : Buffer.from(cleanSecret, 'utf8');

  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return code.toString().padStart(6, '0');
}

// Valida código TOTP com tolerância de janela de tempo (±1 intervalo de 30s)
function verifyTOTP(token, secret, window = 1) {
  if (!token || !secret) return false;
  const cleanToken = token.toString().trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;

  const now = Date.now();
  for (let error = -window; error <= window; error++) {
    const expected = generateTOTP(secret, 30, now + error * 30000);
    if (expected && crypto.timingSafeEqual(Buffer.from(cleanToken), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

// Validação unificada de 2FA/OTP:
// 1. Verifica token TOTP RFC 6238 (Google Authenticator / Authy / 1Password)
// 2. OU verifica PIN de 6 dígitos seguro do membro (fator de contingência)
function verifyMember2FA(member, otpCode) {
  if (!member || !otpCode) return false;
  const cleanOtp = otpCode.toString().trim();
  if (!/^\d{6}$/.test(cleanOtp)) return false;

  // 1. Testa TOTP se houver segredo cadastrado
  if (member.twoFactorSecret) {
    if (verifyTOTP(cleanOtp, member.twoFactorSecret)) {
      return true;
    }
  }

  // 2. Testa PIN do membro (fator secundário de 6 dígitos)
  if (member.pinHash) {
    const bcrypt = require('bcryptjs');
    try {
      if (bcrypt.compareSync(cleanOtp, member.pinHash)) {
        return true;
      }
    } catch (_) {}
  }

  return false;
}

// ==========================================
// GERENCIAMENTO DE TOKEN JWT & SESSÃO
// ==========================================

function generateMemberToken(member) {
  // Fingerprint baseado no hash de senha e de PIN para invalidar tokens antigos caso credenciais mudem
  const creds = `${member.passwordHash || ''}:${member.pinHash || ''}:${member.twoFactorSecret || ''}`;
  const credsFingerprint = crypto.createHash('sha256').update(creds).digest('hex').substring(0, 12);

  return jwt.sign(
    {
      id: member.id,
      username: member.username,
      name: member.name,
      role: member.role,
      level: member.level,
      credsFingerprint
    },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

function verifyMemberToken(token) {
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const member = db.findMember(decoded.id);
    if (!member) return null;

    if (member.status === 'bloqueado' || member.status === 'banido' || member.status === 'inativo') {
      return null;
    }

    if (decoded.credsFingerprint) {
      const currentCreds = `${member.passwordHash || ''}:${member.pinHash || ''}:${member.twoFactorSecret || ''}`;
      const currentFingerprint = crypto.createHash('sha256').update(currentCreds).digest('hex').substring(0, 12);
      if (decoded.credsFingerprint !== currentFingerprint) {
        return null;
      }
    }

    return member;
  } catch (err) {
    return null;
  }
}

// Emissão de Ticket temporário de autenticação para a etapa do PIN Keypad (validade: 5 minutos)
function generateLoginTicket(member) {
  if (!member) return null;
  return jwt.sign(
    {
      id: member.id,
      username: member.username,
      name: member.name,
      role: member.role,
      type: 'login_ticket_step2'
    },
    JWT_SECRET,
    { expiresIn: '5m' }
  );
}

// Validação do Ticket temporário de PIN
function verifyLoginTicket(ticket) {
  if (!ticket) return null;
  try {
    const decoded = jwt.verify(ticket, JWT_SECRET);
    if (!decoded || decoded.type !== 'login_ticket_step2') return null;
    return decoded;
  } catch (err) {
    return null;
  }
}

// ==========================================
// RATE LIMITING & DEFESA CONTRA FORÇA BRUTA
// ==========================================
const failedAttemptsMap = new Map();

function pruneRateLimitMaps() {
  const now = Date.now();
  const maxAge = 15 * 60 * 1000;
  for (const [k, v] of failedAttemptsMap.entries()) {
    if (now - v.lastAttempt > maxAge) {
      failedAttemptsMap.delete(k);
    }
  }
}

const pruneTimer = setInterval(pruneRateLimitMaps, 5 * 60 * 1000);
if (pruneTimer.unref) pruneTimer.unref();

function checkLoginRateLimit(ip, username) {
  const cleanIp = (ip || '127.0.0.1').trim();
  const cleanUser = username ? username.toString().trim().toLowerCase() : null;
  const now = Date.now();
  const cooldown = 5 * 60 * 1000; // 5 minutos de bloqueio após 3 tentativas (anti-brute-force)
  const maxAttempts = 3; // Máximo 3 tentativas antes do bloqueio

  const ipRecord = failedAttemptsMap.get(`ip:${cleanIp}`);
  if (ipRecord && ipRecord.count >= maxAttempts) {
    const elapsed = now - ipRecord.lastAttempt;
    if (elapsed < cooldown) {
      const waitSeconds = Math.ceil((cooldown - elapsed) / 1000);
      return {
        allowed: false,
        error: `Acesso bloqueado por segurança: Múltiplas falhas a partir deste endereço IP. Aguarde ${waitSeconds}s antes de tentar novamente.`
      };
    } else {
      failedAttemptsMap.delete(`ip:${cleanIp}`);
    }
  }

  if (cleanUser) {
    const userRecord = failedAttemptsMap.get(`user:${cleanUser}`);
    if (userRecord && userRecord.count >= maxAttempts) {
      const elapsed = now - userRecord.lastAttempt;
      if (elapsed < cooldown) {
        const waitSeconds = Math.ceil((cooldown - elapsed) / 1000);
        return {
          allowed: false,
          error: `Acesso temporariamente bloqueado para o codinome '${cleanUser}': Múltiplas falhas registradas. Aguarde ${waitSeconds}s.`
        };
      } else {
        failedAttemptsMap.delete(`user:${cleanUser}`);
      }
    }
  }

  return { allowed: true };
}

function recordLoginFailure(ip, username) {
  const cleanIp = (ip || '127.0.0.1').trim();
  const now = Date.now();

  const ipKey = `ip:${cleanIp}`;
  const ipRecord = failedAttemptsMap.get(ipKey) || { count: 0, lastAttempt: now };
  ipRecord.count += 1;
  ipRecord.lastAttempt = now;
  failedAttemptsMap.set(ipKey, ipRecord);

  if (username) {
    const cleanUser = username.toString().trim().toLowerCase();
    const userKey = `user:${cleanUser}`;
    const userRecord = failedAttemptsMap.get(userKey) || { count: 0, lastAttempt: now };
    userRecord.count += 1;
    userRecord.lastAttempt = now;
    failedAttemptsMap.set(userKey, userRecord);
  }
}

function clearLoginFailures(ip, username) {
  const cleanIp = (ip || '127.0.0.1').trim();
  failedAttemptsMap.delete(`ip:${cleanIp}`);
  if (username) {
    const cleanUser = username.toString().trim().toLowerCase();
    failedAttemptsMap.delete(`user:${cleanUser}`);
  }
}

function getLoginAttemptsLeft(ip, username) {
  const cleanIp = (ip || '127.0.0.1').trim();
  const cleanUser = username ? username.toString().trim().toLowerCase() : null;
  const ipRecord = failedAttemptsMap.get(`ip:${cleanIp}`);
  const userRecord = cleanUser ? failedAttemptsMap.get(`user:${cleanUser}`) : null;
  const ipCount = (ipRecord && ipRecord.count) || 0;
  const userCount = (userRecord && userRecord.count) || 0;
  const maxAttempts = 3;
  const used = Math.max(ipCount, userCount);
  return Math.max(0, maxAttempts - used);
}

function checkActionRateLimit(key, maxAttempts = 5, cooldownMs = 120000, actionName = 'esta ação') {
  const now = Date.now();
  const record = failedAttemptsMap.get(`act:${key}`);
  if (!record) return { allowed: true };

  if (record.count >= maxAttempts) {
    const elapsed = now - record.lastAttempt;
    if (elapsed < cooldownMs) {
      const waitSeconds = Math.ceil((cooldownMs - elapsed) / 1000);
      return {
        allowed: false,
        error: `Limite de segurança excedido para ${actionName}. Aguarde ${waitSeconds}s antes de tentar novamente.`
      };
    } else {
      failedAttemptsMap.delete(`act:${key}`);
    }
  }
  return { allowed: true };
}

function recordActionFailure(key) {
  const now = Date.now();
  const k = `act:${key}`;
  const record = failedAttemptsMap.get(k) || { count: 0, lastAttempt: now };
  record.count += 1;
  record.lastAttempt = now;
  failedAttemptsMap.set(k, record);
}

function clearActionFailures(key) {
  failedAttemptsMap.delete(`act:${key}`);
}

// ==========================================
// MIDDLEWARES DE AUTORIZAÇÃO E SEGURANÇA
// ==========================================

function requireMemberAuth(req, res, next) {
  let token = null;
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  }
  if (!token && req.cookies && req.cookies.nzi_token) {
    token = req.cookies.nzi_token;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Acesso restrito apenas para membros. Faça login para continuar."
    });
  }

  try {
    const member = verifyMemberToken(token);
    if (!member) {
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros. Sessão expirada ou não autorizada."
      });
    }

    req.member = {
      id: member.id,
      username: member.username,
      name: member.name,
      role: member.role,
      level: member.level,
      status: member.status,
      profitShare: member.profitShare,
      weeklyEarnings: member.weeklyEarnings,
      avatarUrl: member.avatarUrl || null,
      isAdmin: member.level <= 2
    };
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: "Acesso restrito apenas para membros. Sessão expirada ou inválida."
    });
  }
}

function requireMinLevel(maxLevel) {
  return (req, res, next) => {
    if (!req.member) {
      return res.status(401).json({
        success: false,
        error: "Acesso restrito apenas para membros."
      });
    }
    if (req.member.level > maxLevel) {
      return res.status(403).json({
        success: false,
        error: "Acesso restrito: Ação restrita a hierarquias superiores da Nzi Mafia."
      });
    }
    next();
  };
}

function requireAdminAuth(req, res, next) {
  requireMemberAuth(req, res, () => {
    if (!req.member || req.member.level > 2) {
      return res.status(403).json({
        success: false,
        error: "Acesso negado: Somente administradores autorizados (Dono e Fundador) podem gerenciar o painel de Operações."
      });
    }
    next();
  });
}

function optionalMemberAuth(req, res, next) {
  let token = null;
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  }
  if (!token && req.cookies && req.cookies.nzi_token) {
    token = req.cookies.nzi_token;
  }
  if (token) {
    const member = verifyMemberToken(token);
    if (member) {
      req.member = {
        id: member.id,
        username: member.username,
        name: member.name,
        role: member.role,
        level: member.level,
        status: member.status,
        profitShare: member.profitShare,
        weeklyEarnings: member.weeklyEarnings,
        avatarUrl: member.avatarUrl || null,
        isAdmin: member.level <= 2
      };
    }
  }
  next();
}

function requireCsrfProtection(req, res, next) {
  const mutationMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
  if (!mutationMethods.includes(req.method)) {
    return next();
  }

  const publicExceptions = ['/api/auth/', '/api/track', '/api/recruitment/apply'];
  if (publicExceptions.some(p => req.path.startsWith(p))) {
    return next();
  }

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return next();
  }

  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  const host = req.headers['host'];

  const isLocal = (h) => h && (h.startsWith('localhost') || h.startsWith('127.0.0.1') || h.startsWith('::1') || h === 'localhost' || h === '127.0.0.1');

  if (isLocal(host)) {
    if (!origin && !referer) return next();
    if (origin) {
      try { if (isLocal(new URL(origin).host)) return next(); } catch (e) {}
    }
    if (referer) {
      try { if (isLocal(new URL(referer).host)) return next(); } catch (e) {}
    }
  }

  if (origin) {
    try {
      const originHost = new URL(origin).host;
      if (originHost === host) return next();
    } catch (e) {}
  } else if (referer) {
    try {
      const refererHost = new URL(referer).host;
      if (refererHost === host) return next();
    } catch (e) {}
  }

  return res.status(403).json({
    success: false,
    error: "Ação bloqueada: Validação de segurança de origem falhou (Proteção Anti-CSRF)."
  });
}

function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '';
  const trimmed = url.trim();
  if (/[\s\x00-\x1f\x7f]/.test(trimmed)) return '';
  if (/^(javascript|data|vbscript|file):/i.test(trimmed)) return '';
  if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.startsWith('/\\')) {
    return trimmed;
  }
  if (/^https?:\/\/[a-z0-9\-._~:/?#[\]@!$&'()*+,;=]+$/i.test(trimmed)) {
    return trimmed;
  }
  return '';
}

// ==========================================
// CRIPTOGRAFIA AES-256-GCM PARA CREDENCIAIS
// ==========================================
const ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();

function encryptSecret(text) {
  if (!text) return { encrypted: '', iv: '', tag: '' };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(String(text), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return {
    encrypted,
    iv: iv.toString('hex'),
    tag
  };
}

function decryptSecret(encrypted, ivHex, tagHex) {
  if (!encrypted || !ivHex || !tagHex) return '';
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    return '[Falha na decriptação da credencial]';
  }
}

module.exports = {
  JWT_SECRET,
  validatePinFormat,
  validatePassword,
  getClientIp,
  generateTotpSecret,
  generateTOTP,
  verifyTOTP,
  verifyMember2FA,
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
  encryptSecret,
  decryptSecret
};
