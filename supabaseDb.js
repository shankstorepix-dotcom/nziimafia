const bcrypt = require('bcryptjs');
const { getSupabase, isSupabaseConfigured } = require('./supabaseClient');

// ==========================================
// HELPERS DE CONVERSÃO SNAKE_CASE <-> CAMELCASE
// ==========================================

function mapMemberFromDb(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    name: row.name,
    role: row.role,
    level: row.level,
    pinHash: row.pin_hash,
    passwordHash: row.password_hash,
    defaultPinHint: row.default_pin_hint,
    twoFactorSecret: row.two_factor_secret || undefined,
    trustedIp: row.trusted_ip || null,
    trustedHwid: row.trusted_hwid || null,
    avatarUrl: row.avatar_url || null,
    status: row.status,
    profitShare: row.profit_share,
    weeklyEarnings: Number(row.weekly_earnings) || 0,
    lastLogin: row.last_login,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapMemberToDb(m) {
  return {
    id: m.id,
    username: m.username,
    name: m.name,
    role: m.role,
    level: m.level,
    pin_hash: m.pinHash || m.pin_hash,
    password_hash: m.passwordHash || m.password_hash || null,
    default_pin_hint: m.defaultPinHint || m.default_pin_hint || null,
    two_factor_secret: m.twoFactorSecret || m.two_factor_secret || null,
    trusted_ip: m.trustedIp || m.trusted_ip || null,
    trusted_hwid: m.trustedHwid || m.trusted_hwid || null,
    avatar_url: m.avatarUrl || m.avatar_url || null,
    status: m.status || 'online',
    profit_share: m.profitShare || m.profit_share || '4%',
    weekly_earnings: Number(m.weeklyEarnings || m.weekly_earnings || 0),
    last_login: m.lastLogin || m.last_login || null
  };
}

function mapPostFromDb(row) {
  if (!row) return null;
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    category: row.category,
    status: row.status,
    image: row.image || '',
    link: row.link || '',
    publishedAt: row.published_at,
    author: row.author,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapEventFromDb(row) {
  if (!row) return null;
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    eventDate: row.event_date,
    timezone: row.timezone,
    startTime: row.start_time,
    endTime: row.end_time,
    status: row.status,
    published: row.published,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapDiscordFromDb(row, includeSecrets = false) {
  if (!row) return null;
  const item = {
    id: row.id,
    title: row.title,
    email: row.email || '',
    botTag: row.bot_tag,
    description: row.description,
    permissions: row.permissions,
    status: row.status,
    isPublicDisclosed: row.is_public_disclosed,
    isReward: row.is_reward !== undefined ? row.is_reward : true,
    claimed: Boolean(row.claimed),
    claimedBy: row.claimed_by || null,
    claimedById: row.claimed_by_id || null,
    claimedByName: row.claimed_by_name || null,
    claimedAt: row.claimed_at || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
  if (includeSecrets) {
    item.encryptedSecret = row.encrypted_secret;
    item.secretIv = row.secret_iv;
    item.secretTag = row.secret_tag;
  }
  return item;
}

// ==========================================
// OPERAÇÕES DE AUTENTICAÇÃO E MEMBROS
// ==========================================

async function findMember(identifier) {
  const supabase = getSupabase();
  if (!supabase || !identifier) return null;

  const clean = identifier.toString().trim().toLowerCase();

  const { data, error } = await supabase
    .from('members')
    .select('*')
    .or(`id.ilike.${clean},username.ilike.${clean},name.ilike.${clean}`)
    .limit(1)
    .maybeSingle();

  if (error || !data) return null;
  return mapMemberFromDb(data);
}

function verifyMemberPin(member, pin) {
  if (!member || !member.pinHash || !pin) return false;
  return bcrypt.compareSync(pin.toString().trim(), member.pinHash);
}

async function updateMemberPin(identifier, newPin) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  if (!/^\d{6}$/.test(newPin)) {
    throw new Error("O PIN deve conter exatamente 6 dígitos numéricos.");
  }

  const member = await findMember(identifier);
  if (!member) throw new Error("Membro não encontrado na organização.");

  const salt = bcrypt.genSaltSync(10);
  const pinHash = bcrypt.hashSync(newPin.toString().trim(), salt);

  const { data, error } = await supabase
    .from('members')
    .update({
      pin_hash: pinHash,
      default_pin_hint: null,
      updated_at: new Date().toISOString()
    })
    .eq('id', member.id)
    .select()
    .single();

  if (error) throw new Error(`Falha ao atualizar PIN no Supabase: ${error.message}`);
  return mapMemberFromDb(data);
}

async function recordLogin(username, ip, success = true) {
  const supabase = getSupabase();
  if (!supabase) return null;

  const member = await findMember(username);
  const now = new Date();
  const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);

  if (member && success) {
    await supabase
      .from('members')
      .update({
        last_login: timestamp,
        status: 'online',
        updated_at: now.toISOString()
      })
      .eq('id', member.id);
  }

  const logEntry = {
    id: `log_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    member: member ? member.name : username,
    role: member ? member.role : 'DESCONHECIDO',
    action: "LOGIN",
    status: success ? "SUCESSO" : "BLOQUEADO",
    ip: ip || "127.0.0.1",
    timestamp: timestamp
  };

  await supabase.from('audit_logs').insert([logEntry]);
  return logEntry;
}

async function addMember({ username, name, role, level, pin }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  if (!username || !username.trim()) throw new Error("Codinome de usuário é obrigatório.");
  if (!pin || !/^\d{6}$/.test(pin.toString().trim())) {
    throw new Error("O PIN deve conter exatamente 6 dígitos numéricos.");
  }

  const existing = await findMember(username);
  if (existing) throw new Error("Já existe um integrante cadastrado com este codinome.");

  const salt = bcrypt.genSaltSync(10);
  const pinHash = bcrypt.hashSync(pin.toString().trim(), salt);
  const numLevel = Number(level) || 2;

  const memberRow = {
    id: `mem_${Date.now()}`,
    username: username.trim().toLowerCase(),
    name: name ? name.trim() : username.trim(),
    role: role || (numLevel === 1 ? "Owner" : (numLevel === 2 ? "Founder" : "Member")),
    level: numLevel,
    pin_hash: pinHash,
    status: "online",
    profit_share: numLevel === 1 ? "40%" : (numLevel === 2 ? "25%" : "4%"),
    weekly_earnings: 0,
    created_at: new Date().toISOString()
  };

  const { data, error } = await supabase
    .from('members')
    .insert([memberRow])
    .select()
    .single();

  if (error) throw new Error(`Erro ao cadastrar membro no Supabase: ${error.message}`);
  return mapMemberFromDb(data);
}

async function updateMemberStatus(identifier, newStatus) {
  const supabase = getSupabase();
  if (!supabase) return null;

  const member = await findMember(identifier);
  if (!member) return null;

  const { data, error } = await supabase
    .from('members')
    .update({ status: newStatus, updated_at: new Date().toISOString() })
    .eq('id', member.id)
    .select()
    .single();

  if (error) return null;
  return mapMemberFromDb(data);
}

async function getMembers() {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('members')
    .select('*')
    .order('level', { ascending: true });

  if (error || !data) return [];
  return data.map(mapMemberFromDb);
}

// ==========================================
// OPERAÇÕES DO COFRE & TRANSAÇÕES
// ==========================================

async function getFinancials() {
  const supabase = getSupabase();
  if (!supabase) return null;

  const { data, error } = await supabase
    .from('financials')
    .select('*')
    .eq('id', 1)
    .single();

  if (error || !data) {
    return {
      totalVault: 1290000,
      weeklyProfit: 165000,
      currency: "BRL",
      lastDistribution: "2026-10-16 23:45",
      rules: {
        level1: "40% (Owner)",
        level2: "25% (Founder)",
        level3: "15% total (7.5% por Posse)",
        level4: "20% total (4% por Membro)"
      }
    };
  }

  return {
    totalVault: Number(data.total_vault),
    weeklyProfit: Number(data.weekly_profit),
    currency: data.currency,
    lastDistribution: data.last_distribution,
    rules: data.rules
  };
}

async function addTransaction({ type, amount, description, author }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const parsedAmount = Number(amount);
  if (isNaN(parsedAmount) || parsedAmount <= 0) {
    throw new Error("Valor inválido.");
  }

  const now = new Date();
  const timestamp = now.toISOString().replace('T', ' ').substring(0, 16);
  const tx = {
    id: `tx_${Date.now()}`,
    type: type === 'OUT' ? 'OUT' : 'IN',
    amount: parsedAmount,
    description: description || "Sem descrição",
    date: timestamp,
    author: author || "Sistema"
  };

  const { error: txError } = await supabase.from('transactions').insert([tx]);
  if (txError) throw new Error(`Erro ao registrar transação no Supabase: ${txError.message}`);

  // Atualiza saldo no cofre
  const fin = await getFinancials();
  const newVault = tx.type === 'IN' 
    ? fin.totalVault + parsedAmount 
    : Math.max(0, fin.totalVault - parsedAmount);
  const newProfit = tx.type === 'IN' ? fin.weeklyProfit + parsedAmount : fin.weeklyProfit;

  await supabase
    .from('financials')
    .update({
      total_vault: newVault,
      weekly_profit: newProfit,
      updated_at: new Date().toISOString()
    })
    .eq('id', 1);

  return tx;
}

async function getTransactions() {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('transactions')
    .select('*')
    .order('created_at', { ascending: false });

  if (error || !data) return [];
  return data;
}

// ==========================================
// OPERAÇÕES & MURAL
// ==========================================

async function getOperations() {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('operations')
    .select('*')
    .order('created_at', { ascending: false });

  if (error || !data) return [];
  return data.map(o => ({
    id: o.id,
    title: o.title,
    status: o.status,
    target: Number(o.target),
    leader: o.leader,
    priority: o.priority,
    description: o.description
  }));
}

async function addOperation({ title, target, leader, priority, description }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const op = {
    id: `op_${Date.now()}`,
    title: title ? title.trim() : "Nova Operação",
    status: "Em andamento",
    target: Number(target) || 50000,
    leader: leader || "Liderança",
    priority: priority || "ALTA",
    description: description ? description.trim() : "Operação financeira interna"
  };

  const { error } = await supabase.from('operations').insert([op]);
  if (error) throw new Error(`Erro ao cadastrar operação: ${error.message}`);
  return op;
}

async function updateOperation(id, updates) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const payload = { ...updates, updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from('operations')
    .update(payload)
    .eq('id', id)
    .select()
    .single();

  if (error) throw new Error(`Erro ao atualizar operação: ${error.message}`);
  return data;
}

async function getAnnouncements() {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('announcements')
    .select('*')
    .order('pinned', { ascending: false })
    .order('created_at', { ascending: false });

  if (error || !data) return [];
  return data;
}

async function addAnnouncement({ author, role, title, content, pinned = false }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const now = new Date();
  const timestamp = now.toISOString().replace('T', ' ').substring(0, 16);
  const announcement = {
    id: `ann_${Date.now()}`,
    author,
    role,
    date: timestamp,
    title: title.trim(),
    content: content.trim(),
    pinned: Boolean(pinned)
  };

  const { error } = await supabase.from('announcements').insert([announcement]);
  if (error) throw new Error(`Erro ao publicar comunicado: ${error.message}`);
  return announcement;
}

async function getAuditLogs() {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('audit_logs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(100);

  if (error || !data) return [];
  return data;
}

// ==========================================
// PUBLICAÇÕES (POSTS)
// ==========================================

async function getPosts({ category, status, search, includeUnpublished = false } = {}) {
  const supabase = getSupabase();
  if (!supabase) return [];

  let query = supabase.from('posts').select('*');

  if (!includeUnpublished) {
    query = query.eq('status', 'Publicado');
  } else if (status && status !== 'Todos') {
    query = query.ilike('status', status);
  }

  if (category && category !== 'Todos') {
    query = query.ilike('category', category);
  }

  const { data, error } = await query.order('created_at', { ascending: false });
  if (error || !data) return [];

  let list = data.map(mapPostFromDb);
  if (search) {
    const q = search.toLowerCase().trim();
    list = list.filter(p =>
      (p.title && p.title.toLowerCase().includes(q)) ||
      (p.description && p.description.toLowerCase().includes(q)) ||
      (p.category && p.category.toLowerCase().includes(q))
    );
  }
  return list;
}

async function getPostById(id) {
  const supabase = getSupabase();
  if (!supabase || !id) return null;

  const { data, error } = await supabase
    .from('posts')
    .select('*')
    .eq('id', id)
    .maybeSingle();

  if (error || !data) return null;
  return mapPostFromDb(data);
}

async function addPost({ title, description, category, image, link, status, author }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const now = new Date();
  const timestamp = now.toISOString().replace('T', ' ').substring(0, 16);
  const row = {
    id: `post_${Date.now()}`,
    title: title ? title.trim() : "Sem título",
    description: description ? description.trim() : "",
    category: category || "Painel",
    status: status || "Publicado",
    image: image ? image.trim() : "",
    link: link ? link.trim() : "",
    published_at: timestamp,
    author: author || "Diretoria"
  };

  const { data, error } = await supabase.from('posts').insert([row]).select().single();
  if (error) throw new Error(`Erro ao criar publicação: ${error.message}`);
  return mapPostFromDb(data);
}

async function updatePost(id, updates) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const payload = {};
  if (updates.title !== undefined) payload.title = updates.title.trim();
  if (updates.description !== undefined) payload.description = updates.description.trim();
  if (updates.category !== undefined) payload.category = updates.category;
  if (updates.image !== undefined) payload.image = updates.image ? updates.image.trim() : "";
  if (updates.link !== undefined) payload.link = updates.link ? updates.link.trim() : "";
  if (updates.status !== undefined) payload.status = updates.status;
  payload.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('posts')
    .update(payload)
    .eq('id', id)
    .select()
    .single();

  if (error) throw new Error(`Erro ao atualizar publicação: ${error.message}`);
  return mapPostFromDb(data);
}

async function deletePost(id) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const { error } = await supabase.from('posts').delete().eq('id', id);
  if (error) throw new Error(`Erro ao excluir publicação: ${error.message}`);
  return true;
}

async function togglePublishPost(id) {
  const post = await getPostById(id);
  if (!post) throw new Error("Publicação não encontrada.");

  const newStatus = post.status === 'Publicado' ? 'Despublicado' : 'Publicado';
  return updatePost(id, { status: newStatus });
}

// ==========================================
// EVENTOS & TEMPORIZADORES
// ==========================================

async function getEvents({ status, search, includeUnpublished = false } = {}) {
  const supabase = getSupabase();
  if (!supabase) return [];

  let query = supabase.from('events').select('*');

  if (!includeUnpublished) {
    query = query.eq('published', true);
  }
  if (status && status !== 'Todos') {
    query = query.ilike('status', status);
  }

  const { data, error } = await query.order('event_date', { ascending: true });
  if (error || !data) return [];

  let list = data.map(mapEventFromDb);
  if (search) {
    const q = search.toLowerCase().trim();
    list = list.filter(e =>
      (e.title && e.title.toLowerCase().includes(q)) ||
      (e.description && e.description.toLowerCase().includes(q))
    );
  }
  return list;
}

async function getEventById(id) {
  const supabase = getSupabase();
  if (!supabase || !id) return null;

  const { data, error } = await supabase.from('events').select('*').eq('id', id).maybeSingle();
  if (error || !data) return null;
  return mapEventFromDb(data);
}

async function addEvent({ title, description, eventDate, timezone, startTime, endTime, status, published = true }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const row = {
    id: `evt_${Date.now()}`,
    title: title ? title.trim() : "Novo Evento",
    description: description ? description.trim() : "",
    event_date: eventDate || new Date().toISOString(),
    timezone: timezone || "America/Sao_Paulo (GMT-3)",
    start_time: startTime || "23:00",
    end_time: endTime || "01:00",
    status: status || "Confirmado",
    published: published !== false
  };

  const { data, error } = await supabase.from('events').insert([row]).select().single();
  if (error) throw new Error(`Erro ao agendar evento: ${error.message}`);
  return mapEventFromDb(data);
}

async function updateEvent(id, updates) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const payload = {};
  if (updates.title !== undefined) payload.title = updates.title.trim();
  if (updates.description !== undefined) payload.description = updates.description.trim();
  if (updates.eventDate !== undefined) payload.event_date = updates.eventDate;
  if (updates.timezone !== undefined) payload.timezone = updates.timezone;
  if (updates.startTime !== undefined) payload.start_time = updates.startTime;
  if (updates.endTime !== undefined) payload.end_time = updates.endTime;
  if (updates.status !== undefined) payload.status = updates.status;
  if (updates.published !== undefined) payload.published = Boolean(updates.published);
  payload.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('events')
    .update(payload)
    .eq('id', id)
    .select()
    .single();

  if (error) throw new Error(`Erro ao atualizar evento: ${error.message}`);
  return mapEventFromDb(data);
}

async function deleteEvent(id) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const { error } = await supabase.from('events').delete().eq('id', id);
  if (error) throw new Error(`Erro ao excluir evento: ${error.message}`);
  return true;
}

async function togglePublishEvent(id) {
  const event = await getEventById(id);
  if (!event) throw new Error("Evento não encontrado.");
  return updateEvent(id, { published: !event.published });
}

// ==========================================
// CENTRAL DE LINKS
// ==========================================

async function getLinks() {
  const supabase = getSupabase();
  if (!supabase) return {};

  const { data, error } = await supabase.from('links').select('*');
  if (error || !data) return {};

  const result = {};
  data.forEach(item => {
    result[item.key] = {
      key: item.key,
      name: item.name,
      icon: item.icon,
      url: item.url,
      description: item.description,
      isAvailable: item.is_available
    };
  });
  return result;
}

async function updateLink(key, { url, description, name }) {
  const supabase = getSupabase();
  if (!supabase) throw new Error("Supabase não está conectado.");

  const payload = { updated_at: new Date().toISOString() };
  if (url !== undefined) payload.url = url.trim();
  if (description !== undefined) payload.description = description.trim();
  if (name !== undefined) payload.name = name.trim();

  const { data, error } = await supabase
    .from('links')
    .update(payload)
    .eq('key', key.toLowerCase())
    .select()
    .single();

  if (error) throw new Error(`Erro ao atualizar link no Supabase: ${error.message}`);
  return {
    key: data.key,
    name: data.name,
    icon: data.icon,
    url: data.url,
    description: data.description,
    isAvailable: data.is_available
  };
}

// ==========================================
// CONTAS DISCORD
// ==========================================

async function getDiscordAccounts(isAdmin = false) {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('discord_accounts')
    .select('*')
    .order('created_at', { ascending: true });

  if (error || !data) return [];
  return data
    .filter(row => isAdmin || row.is_public_disclosed)
    .map(row => mapDiscordFromDb(row, isAdmin));
}

// ==========================================
// ESTATÍSTICAS DO DASHBOARD EM TEMPO REAL
// ==========================================

async function getDashboardStats() {
  const posts = await getPosts({ includeUnpublished: true });
  const allEvents = await getEvents({ includeUnpublished: true });
  const links = await getLinks();

  const postsByCategory = {
    painel: posts.filter(p => p.category.toLowerCase() === 'painel' && p.status === 'Publicado').length,
    discord: posts.filter(p => p.category.toLowerCase() === 'conta discord' && p.status === 'Publicado').length,
    links: posts.filter(p => p.category.toLowerCase() === 'central de links' && p.status === 'Publicado').length,
    eventos: posts.filter(p => p.category.toLowerCase() === 'eventos' && p.status === 'Publicado').length
  };

  const activeEventsCount = allEvents.filter(e => e.status === 'Em andamento' && e.published).length;
  const confirmedEventsCount = allEvents.filter(e => e.status === 'Confirmado' && e.published).length;
  const scheduledEventsCount = allEvents.filter(e => e.status === 'Agendado' && e.published).length;
  const finishedEventsCount = allEvents.filter(e => e.status === 'Finalizado' && e.published).length;

  const publishedPosts = posts.filter(p => p.status === 'Publicado');
  const latestPosts = publishedPosts.slice(0, 5);

  const availableLinksCount = Object.values(links).filter(l => l.isAvailable).length;

  return {
    totalPosts: publishedPosts.length,
    postsByCategory,
    eventsStats: {
      total: allEvents.length,
      active: activeEventsCount,
      confirmed: confirmedEventsCount,
      scheduled: scheduledEventsCount,
      finished: finishedEventsCount
    },
    latestPosts,
    availableLinksCount,
    discordAccountsCount: (await getDiscordAccounts(false)).length
  };
}

module.exports = {
  // Conversões
  mapMemberFromDb,
  mapMemberToDb,
  mapPostFromDb,
  mapEventFromDb,
  // Membros & Auth
  findMember,
  verifyMemberPin,
  updateMemberPin,
  recordLogin,
  addMember,
  updateMemberStatus,
  getMembers,
  // Cofre & Financeiro
  getFinancials,
  addTransaction,
  getTransactions,
  // Operações & Mural
  getOperations,
  addOperation,
  updateOperation,
  getAnnouncements,
  addAnnouncement,
  getAuditLogs,
  // Publicações
  getPosts,
  getPostById,
  addPost,
  updatePost,
  deletePost,
  togglePublishPost,
  // Eventos
  getEvents,
  getEventById,
  addEvent,
  updateEvent,
  deleteEvent,
  togglePublishEvent,
  // Links
  getLinks,
  updateLink,
  // Discord
  getDiscordAccounts,
  // Estatísticas
  getDashboardStats
};
