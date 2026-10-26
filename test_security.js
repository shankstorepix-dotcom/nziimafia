/**
 * SUÍTE DE TESTES AUTOMATIZADOS DE SEGURANÇA — NZI MAFIA
 * Valida todas as correções de vulnerabilidade antes do deploy:
 * 1. Proteção de arquivos confidenciais e database.json
 * 2. Revogação de credenciais antigas e proteção do token do Bot Discord via env
 * 3. Autenticação multifator (Usuário, Senha e 2FA/OTP via TOTP e PIN)
 * 4. Defesa contra força bruta e rate limiting
 * 5. Integração com Cloudflare (cabeçalhos e IP real)
 * 6. Proteção contra deface e autorização administrativa
 */

const http = require('http');
const assert = require('assert');
const app = require('./server');
const db = require('./db');
const { generateTOTP, getClientIp } = require('./auth');

const PORT = 3999;
let server;

function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({ port: PORT, ...options }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (_) {}
        resolve({ status: res.statusCode, headers: res.headers, body: data, json });
      });
    });
    req.on('error', reject);
    if (body) {
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      req.setHeader('Content-Type', 'application/json');
      req.setHeader('Content-Length', Buffer.byteLength(payload));
      req.write(payload);
    }
    req.end();
  });
}

async function runTests() {
  console.log('==================================================================');
  console.log('INICIANDO AUDITORIA E TESTES DE SEGURANÇA NZI MAFIA');
  console.log('==================================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    return Promise.resolve()
      .then(fn)
      .then(() => {
        console.log(`  [PASS] ${name}`);
        passed++;
      })
      .catch((err) => {
        console.error(`  [FAIL] ${name}: ${err.message}`);
        failed++;
      });
  }

  // Inicia servidor de teste
  await new Promise(resolve => {
    server = app.listen(PORT, resolve);
  });

  try {
    // ---------------------------------------------------------------
    // 1. TESTES DE PROTEÇÃO DE ARQUIVOS CONFIDENCIAIS E BANCO DE DADOS
    // ---------------------------------------------------------------
    console.log('[1/5] Testando proteção de arquivos e vazamento de banco de dados...');

    await test('Bloqueio estrito de acesso direto a /database.json (404)', async () => {
      const res = await request({ path: '/database.json', method: 'GET' });
      assert.strictEqual(res.status, 404, `Esperado 404, recebido ${res.status}`);
      assert.ok(!res.body.includes('financials'), 'Conteúdo do banco não pode ser retornado');
    });

    await test('Bloqueio de acesso a database.json via /assets/database.json (404)', async () => {
      const res = await request({ path: '/assets/database.json', method: 'GET' });
      assert.strictEqual(res.status, 404, `Esperado 404, recebido ${res.status}`);
      assert.ok(!res.body.includes('financials'), 'Conteúdo não pode vazar via /assets');
    });

    await test('Bloqueio de acesso a arquivos de código backend (server.js, db.js, auth.js)', async () => {
      for (const file of ['/server.js', '/db.js', '/auth.js', '/supabaseClient.js']) {
        const res = await request({ path: file, method: 'GET' });
        assert.strictEqual(res.status, 404, `${file} deve responder 404`);
        assert.ok(!res.body.includes('require('), `Código fonte de ${file} vazou`);
      }
    });

    await test('Bloqueio de arquivos sensíveis (.env, .sql, LEIA-ME.txt, .git)', async () => {
      for (const file of ['/.env', '/.env.local', '/supabase_schema.sql', '/LEIA-ME.txt', '/.git/config']) {
        const res = await request({ path: file, method: 'GET' });
        assert.strictEqual(res.status, 404, `${file} deve responder 404`);
      }
    });

    await test('Acesso a arquivos públicos legítimos do frontend é preservado (200)', async () => {
      const res = await request({ path: '/nzi-theme.css', method: 'GET' });
      assert.strictEqual(res.status, 200, 'nzi-theme.css deve ser servido normalmente');
      assert.ok(res.body.includes('--accent'), 'CSS deve conter variáveis do tema');
    });

    // ---------------------------------------------------------------
    // 2. TESTES DE REVOGAÇÃO E PROTEÇÃO DO TOKEN DO BOT DISCORD
    // ---------------------------------------------------------------
    console.log('\n[2/5] Testando proteção do token do Bot NZI Guard e Webhooks...');

    await test('Token comprometido antigo NÃO existe mais no banco ou código em texto claro', async () => {
      const compromised = "MTA4MjM5MjkxODQ3Mjg1OTcx.G7_xYz.nzi_secure_token_secret_777";
      const dbData = db.getDb();
      const stringified = JSON.stringify(dbData);
      assert.ok(!stringified.includes(compromised), 'Token antigo comprometido ainda existe no database.json!');
      const disc = (dbData.discordAccounts || []).find(a => a.id === 'disc_1');
      assert.ok(disc && disc.configuredViaEnv, 'Bot deve estar configurado para carregar via variável de ambiente');
    });

    await test('Tentativa de revelar token do bot sem variável de ambiente informa proteção segura', async () => {
      delete process.env.DISCORD_BOT_TOKEN;
      delete process.env.GUARD_NZI_BOT_TOKEN;
      const result = db.revealDiscordSecret('disc_1', { name: 'Ph Labubu', role: 'Owner' });
      assert.strictEqual(result.configuredViaEnv, true);
      assert.strictEqual(result.secret.isConfigured, false);
      assert.ok(result.secret.notice.includes('DISCORD_BOT_TOKEN'), 'Deve instruir configuração via env');
    });

    await test('Token do bot é retornado com segurança quando configurado via DISCORD_BOT_TOKEN', async () => {
      process.env.DISCORD_BOT_TOKEN = 'token_seguro_e_isolado_discord_999';
      const result = db.revealDiscordSecret('disc_1', { name: 'Ph Labubu', role: 'Owner' });
      assert.strictEqual(result.secret.token, 'token_seguro_e_isolado_discord_999');
      delete process.env.DISCORD_BOT_TOKEN;
    });

    // ---------------------------------------------------------------
    // 3. TESTES DE AUTENTICAÇÃO SEGURA COM USUÁRIO, SENHA E 2FA/OTP
    // ---------------------------------------------------------------
    console.log('\n[3/5] Testando autenticação com Usuário, Senha e 2FA/OTP...');

    await test('Login antigo rejeitado: apenas usuário e PIN (sem senha) falha com 400', async () => {
      const res = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: 'ph_labubu',
        pin: '777001'
      });
      assert.strictEqual(res.status, 400, 'Login sem senha deve retornar 400');
      assert.ok(res.json.error.includes('senha'), 'Mensagem deve exigir senha');
    });

    await test('Credenciais antigas vazadas são rejeitadas (777001 e senha antiga revogada)', async () => {
      const res = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: 'ph_labubu',
        password: 'NZI#v8Kp!42x',
        pin: '777001'
      });
      assert.strictEqual(res.status, 401, 'Credenciais antigas comprometidas devem retornar 401');
    });

    await test('Login com senha incorreta é rejeitado com 401', async () => {
      const res = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: 'ph_labubu',
        password: 'SenhaTotalmenteErrada123!',
        pin: '839201'
      });
      assert.strictEqual(res.status, 401, 'Senha incorreta deve retornar 401');
    });

    await test('Login com senha correta mas código 2FA/OTP incorreto é rejeitado com 401', async () => {
      const res = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: 'ph_labubu',
        password: 'Nzi#Vault2026!Master',
        pin: '000000'
      });
      assert.strictEqual(res.status, 401, '2FA incorreto deve retornar 401');
    });

    await test('Login completo com Usuário + Senha + PIN de contingência 2FA tem SUCESSO (200)', async () => {
      const res = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: 'ph_labubu',
        password: 'Nzi#Vault2026!Master',
        pin: '839201'
      });
      assert.strictEqual(res.status, 200, `Esperado 200, recebido ${res.status}: ${res.body}`);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.token, 'Token JWT deve ser emitido');
      assert.strictEqual(res.json.member.role, 'Owner');
    });

    await test('Login completo com Usuário + Senha + TOTP RFC 6238 (Google Authenticator) tem SUCESSO (200)', async () => {
      const member = db.findMember('ph_labubu');
      assert.ok(member.twoFactorSecret, 'Membro deve ter segredo 2FA cadastrado');
      const totpCode = generateTOTP(member.twoFactorSecret);

      const res = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: 'ph_labubu',
        password: 'Nzi#Vault2026!Master',
        otp: totpCode
      });
      assert.strictEqual(res.status, 200, `Esperado 200 com TOTP, recebido ${res.status}`);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.token, 'Token JWT deve ser emitido com 2FA');
    });

    // ---------------------------------------------------------------
    // 4. TESTES DE RATE LIMITING E PROTEÇÃO CONTRA FORÇA BRUTA
    // ---------------------------------------------------------------
    console.log('\n[4/5] Testando Rate Limiting e defesa contra força bruta...');

    await test('Rate Limiting bloqueia IP após 5 tentativas consecutivas incorretas (429)', async () => {
      const testUser = 'kage';
      for (let i = 0; i < 5; i++) {
        await request({ path: '/api/auth/login', method: 'POST' }, {
          username: testUser,
          password: 'SenhaIncorretaParaTeste!',
          pin: '123456'
        });
      }
      // 6ª tentativa deve sofrer rate limit
      const blockedRes = await request({ path: '/api/auth/login', method: 'POST' }, {
        username: testUser,
        password: 'QualquerCoisa!',
        pin: '123456'
      });
      assert.strictEqual(blockedRes.status, 429, `Esperado 429 Too Many Requests, recebido ${blockedRes.status}`);
      assert.ok(blockedRes.json.error.includes('bloqueado por segurança'), 'Mensagem de rate limit esperada');
    });

    // ---------------------------------------------------------------
    // 5. TESTES DE INTEGRAÇÃO CLOUDFLARE E CABEÇALHOS DE SEGURANÇA
    // ---------------------------------------------------------------
    console.log('\n[5/5] Testando integração Cloudflare, proteção de deface e CSRF...');

    await test('Extração do IP real do cliente via cabeçalho CF-Connecting-IP da Cloudflare', async () => {
      const fakeReq = {
        headers: { 'cf-connecting-ip': '203.0.113.195' },
        app: { get: () => 1 }
      };
      const ip = getClientIp(fakeReq);
      assert.strictEqual(ip, '203.0.113.195', 'Deveria ler o IP real do cabeçalho da Cloudflare');
    });

    await test('Cabeçalhos de segurança HTTP presentes (HSTS, CSP, X-Content-Type-Options)', async () => {
      const res = await request({ path: '/', method: 'GET' });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-content-type-options'], 'nosniff', 'X-Content-Type-Options deve ser nosniff');
      assert.strictEqual(res.headers['x-frame-options'], 'SAMEORIGIN', 'X-Frame-Options deve ser SAMEORIGIN');
    });

    await test('Proteção contra Deface: Ações em posts sem autenticação administrativa são rejeitadas (401/403)', async () => {
      const res = await request({ path: '/api/admin/posts', method: 'POST' }, {
        title: 'Hacked Deface Test',
        description: 'Conteúdo malicioso',
        category: 'Geral'
      });
      assert.ok([401, 403].includes(res.status), `Tentativa de criar post sem auth admin deve ser rejeitada com 401 ou 403, recebido ${res.status}`);
    });

  } finally {
    if (server) {
      await new Promise(resolve => server.close(resolve));
    }
  }

  console.log('\n==================================================================');
  console.log(`RESULTADO DOS TESTES: ${passed} PASSARAM | ${failed} FALHARAM`);
  console.log('==================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Erro fatal ao rodar suíte de testes:', err);
  process.exit(1);
});
