// Importa o database.json LOCAL para o Supabase (rode no seu computador, nunca na Vercel).
//
// Uso:
//   1) Rode o supabase_schema.sql no SQL Editor do Supabase.
//   2) Preencha SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY no .env local.
//   3) npm run supabase:migrate -- --dry-run     (só mostra o que seria enviado)
//      npm run supabase:migrate                  (envia de verdade; pode rodar de novo, é upsert)
//
// Atenção: o database.json contém hashes e segredos 2FA. Este script lê o arquivo local
// e envia direto ao seu projeto Supabase; nada é impresso além de contagens.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { getSupabase, isSupabaseConfigured } = require('./supabaseClient');

const DRY = process.argv.includes('--dry-run');
const FILE = path.join(__dirname, 'database.json');

function ts(v) {
  if (!v) return undefined;
  const d = new Date(String(v).replace(' ', 'T'));
  return isNaN(d.getTime()) ? undefined : d.toISOString();
}
function clean(o) {
  Object.keys(o).forEach(k => o[k] === undefined && delete o[k]);
  return o;
}

async function upsert(supabase, table, rows, conflict) {
  if (!rows.length) return console.log(`- ${table}: 0 registros (nada a enviar)`);
  if (DRY) return console.log(`- ${table}: ${rows.length} registros (dry-run)`);
  for (let i = 0; i < rows.length; i += 200) {
    const chunk = rows.slice(i, i + 200);
    const { error } = await supabase.from(table).upsert(chunk, { onConflict: conflict });
    if (error) throw new Error(`${table}: ${error.message}`);
  }
  console.log(`- ${table}: ${rows.length} registros enviados`);
}

(async () => {
  if (!fs.existsSync(FILE)) throw new Error('database.json não encontrado nesta pasta.');
  if (!DRY && !isSupabaseConfigured()) {
    throw new Error('Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY no .env antes de migrar.');
  }
  const db = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  const supabase = DRY ? null : getSupabase();
  console.log(DRY ? 'DRY-RUN (nada será enviado):' : 'Enviando para o Supabase:');

  await upsert(supabase, 'members', (db.members || []).map(m => clean({
    id: m.id, username: String(m.username).toLowerCase(), name: m.name, role: m.role, level: m.level,
    pin_hash: m.pinHash || null, password_hash: m.passwordHash || null,
    two_factor_secret: m.twoFactorSecret || null,
    trusted_ip: m.trustedIp || null, trusted_hwid: m.trustedHwid || null,
    avatar_url: m.avatarUrl || null,
    status: m.status || 'online', profit_share: m.profitShare || '4%',
    weekly_earnings: Number(m.weeklyEarnings) || 0,
    last_login: m.lastLogin || null, created_at: ts(m.createdAt)
  })), 'id');

  const f = db.financials || {};
  await upsert(supabase, 'financials', [clean({
    id: 1, total_vault: Number(f.totalVault) || 0, weekly_profit: Number(f.weeklyProfit) || 0,
    currency: f.currency || 'BRL', last_distribution: f.lastDistribution || '', rules: f.rules || {}
  })], 'id');

  await upsert(supabase, 'operations', (db.operations || []).map(o => clean({
    id: o.id, title: o.title, status: o.status, target: Number(o.target) || 0,
    leader: o.leader, priority: o.priority, description: o.description || ''
  })), 'id');

  await upsert(supabase, 'announcements', (db.announcements || []).map(a => clean({
    id: a.id, author: a.author, role: a.role, date: a.date, title: a.title,
    content: a.content, pinned: !!a.pinned
  })), 'id');

  await upsert(supabase, 'transactions', (db.transactions || []).map(t => clean({
    id: t.id, type: t.type, amount: Number(t.amount) || 0, description: t.description,
    date: t.date, author: t.author
  })), 'id');

  await upsert(supabase, 'audit_logs', (db.auditLogs || []).map(l => clean({
    id: l.id, member: l.member || '', role: l.role || null, action: l.action, status: l.status,
    ip: l.ip || null, hwid: l.hwid || null, timestamp: l.timestamp || ''
  })), 'id');

  await upsert(supabase, 'posts', (db.posts || []).map(p => clean({
    id: p.id, title: p.title, description: p.description || '', category: p.category,
    status: p.status || 'Publicado', image: p.image || '', link: p.link || '',
    published_at: p.publishedAt || null, author: p.author || null,
    created_at: ts(p.createdAt), updated_at: ts(p.updatedAt)
  })), 'id');

  await upsert(supabase, 'events', (db.events || []).map(e => clean({
    id: e.id, title: e.title, description: e.description || '', event_date: e.eventDate,
    timezone: e.timezone, start_time: e.startTime || null, end_time: e.endTime || null,
    status: e.status, published: e.published !== false,
    created_at: ts(e.createdAt), updated_at: ts(e.updatedAt)
  })), 'id');

  await upsert(supabase, 'links', Object.values(db.links || {}).map(l => clean({
    key: l.key, name: l.name, icon: l.icon, url: l.url,
    description: l.description || '', is_available: l.isAvailable !== false
  })), 'key');

  await upsert(supabase, 'discord_accounts', (db.discordAccounts || []).map(a => clean({
    id: a.id, title: a.title, email: a.email || null, description: a.description || '',
    status: a.status || 'Ativo', is_public_disclosed: a.isPublicDisclosed !== false,
    is_reward: a.isReward !== false, claimed: !!a.claimed,
    claimed_by: a.claimedBy || null, claimed_by_id: a.claimedById || null,
    claimed_by_name: a.claimedByName || null, claimed_at: a.claimedAt || null,
    encrypted_secret: a.encryptedSecret || null, secret_iv: a.secretIv || null,
    secret_tag: a.secretTag || null,
    created_at: ts(a.createdAt), updated_at: ts(a.updatedAt)
  })), 'id');

  console.log(DRY ? '\nDry-run concluído.' : '\nMigração concluída.');
})().catch(err => { console.error('ERRO:', err.message); process.exit(1); });
