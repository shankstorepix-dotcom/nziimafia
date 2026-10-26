const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const supabaseClient = require('./supabaseClient');
const supabaseDb = require('./supabaseDb');

const DB_DIR = __dirname;
const DB_FILE = path.join(__dirname, 'database.json');

function getAuthModule() {
  return require('./auth');
}

function syncToSupabase(actionName, fn) {
  if (!supabaseClient.isSupabaseConfigured()) return;
  Promise.resolve()
    .then(fn)
    .catch(err => {
      console.warn(`[SUPABASE-SYNC] Aviso ao sincronizar ${actionName}:`, err.message);
    });
}

let _supabaseSyncStarted = false;
async function syncFromSupabase() {
  if (_supabaseSyncStarted || !supabaseClient.isSupabaseConfigured()) return;
  _supabaseSyncStarted = true;
  try {
    const test = await supabaseClient.testSupabaseConnection();
    if (!test.connected) return;
    const members = await supabaseDb.getMembers();
    if (members && members.length > 0) {
      const db = getDb();
      db.members = members;
      const posts = await supabaseDb.getPosts({ includeUnpublished: true });
      if (posts && posts.length > 0) db.posts = posts;
      const events = await supabaseDb.getEvents({ includeUnpublished: true });
      if (events && events.length > 0) db.events = events;
      const ops = await supabaseDb.getOperations();
      if (ops && ops.length > 0) db.operations = ops;
      const fin = await supabaseDb.getFinancials();
      if (fin) db.financials = fin;
      const ann = await supabaseDb.getAnnouncements();
      if (ann && ann.length > 0) db.announcements = ann;
      const links = await supabaseDb.getLinks();
      if (links && Object.keys(links).length > 0) db.links = links;
      saveDb(db);
      console.log(`[SUPABASE] Dados sincronizados do Supabase (${members.length} membros).`);
    }
  } catch (err) {
    console.warn('[SUPABASE] Sincronização em segundo plano:', err.message);
  }
}
if (supabaseClient.isSupabaseConfigured()) {
  setTimeout(syncFromSupabase, 300);
}

function encryptSecret(text) {
  return getAuthModule().encryptSecret(text);
}

function decryptSecret(encrypted, ivHex, tagHex) {
  return getAuthModule().decryptSecret(encrypted, ivHex, tagHex);
}

// Membros oficiais da hierarquia Nzi Mafia (sem credenciais em texto claro)
const INITIAL_MEMBERS = [
  {
    id: "mem_1",
    username: "ph_labubu",
    name: "PH LABUBU",
    role: "Owner",
    level: 1,
    status: "online",
    profitShare: "35%",
    weeklyEarnings: 42000
  },
  {
    id: "mem_2",
    username: "dg",
    name: "DG",
    role: "Founder",
    level: 2,
    status: "online",
    profitShare: "25%",
    weeklyEarnings: 30000
  },
  {
    id: "mem_3",
    username: "lifeec",
    name: "LIFEEC",
    role: "Posse",
    level: 3,
    status: "online",
    profitShare: "12%",
    weeklyEarnings: 14400
  },
  {
    id: "mem_4",
    username: "help",
    name: "HELP",
    role: "Posse",
    level: 3,
    status: "online",
    profitShare: "12%",
    weeklyEarnings: 14400
  },
  {
    id: "mem_5",
    username: "necro",
    name: "NECRO",
    role: "Sub-Posse",
    level: 4,
    status: "online",
    profitShare: "5%",
    weeklyEarnings: 6000
  },
  {
    id: "mem_6",
    username: "dahaki",
    name: "DAHAKI",
    role: "Sub-Posse",
    level: 4,
    status: "online",
    profitShare: "5%",
    weeklyEarnings: 6000
  },
  {
    id: "mem_7",
    username: "nana",
    name: "NANA",
    role: "Sub-Posse",
    level: 4,
    status: "online",
    profitShare: "5%",
    weeklyEarnings: 6000
  },
  {
    id: "mem_8",
    username: "qev",
    name: "QEV",
    role: "Member",
    level: 5,
    status: "online",
    profitShare: "1.5%",
    weeklyEarnings: 1800
  },
  {
    id: "mem_9",
    username: "kage",
    name: "KAGE",
    role: "Member",
    level: 5,
    status: "online",
    profitShare: "1.5%",
    weeklyEarnings: 1800
  },
  {
    id: "mem_10",
    username: "luci",
    name: "LUCI",
    role: "Member",
    level: 5,
    status: "online",
    profitShare: "1.5%",
    weeklyEarnings: 1800
  },
  {
    id: "mem_11",
    username: "anny",
    name: "ANNY",
    role: "Member",
    level: 5,
    status: "online",
    profitShare: "1.5%",
    weeklyEarnings: 1800
  }
];

function getInitialData() {
  const { generateTotpSecret } = getAuthModule();
  const members = INITIAL_MEMBERS.map(m => {
    const salt = bcrypt.genSaltSync(12);
    // Credenciais iniciais protegidas - configuradas preferencialmente via ADMIN_INITIAL_PASSWORD
    const initialPass = process.env.ADMIN_INITIAL_PASSWORD || crypto.randomBytes(16).toString('hex');
    const initialPin = String(Math.floor(100000 + Math.random() * 900000));
    return {
      id: m.id,
      username: m.username,
      name: m.name,
      role: m.role,
      level: m.level,
      passwordHash: bcrypt.hashSync(initialPass, salt),
      pinHash: bcrypt.hashSync(initialPin, salt),
      twoFactorSecret: generateTotpSecret(),
      lastLogin: null,
      status: m.status,
      profitShare: m.profitShare,
      weeklyEarnings: m.weeklyEarnings,
      createdAt: new Date().toISOString()
    };
  });

  return {
    financials: {
      totalVault: 1245000,
      weeklyProfit: 120000,
      currency: "BRL",
      lastDistribution: "2026-10-16 23:45",
      rules: {
        level1: "40% (Owner)",
        level2: "25% (Founder)",
        level3: "15% total (7.5% por Posse)",
        level4: "20% total (4% por Membro)"
      }
    },
    operations: [
      {
        id: "op_1",
        title: "Operação Caixa Rápido",
        status: "Em andamento",
        target: 65000,
        leader: "Ph Labubu",
        priority: "ALTA",
        description: "Controle de arrecadação regional e liquidez imediata."
      },
      {
        id: "op_3",
        title: "Expansão da Zona Sul",
        status: "Planejada",
        target: 90000,
        leader: "God & Fact",
        priority: "MÉDIA",
        description: "Prospecção de novos pontos estratégicos de arrecadação."
      }
    ],
    announcements: [
      {
        id: "ann_1",
        author: "Ph Labubu",
        role: "Owner",
        date: "2026-10-16 23:45",
        title: "DIVISÃO DO CAIXA SEMANAL CONCLUÍDA",
        content: "O fechamento semanal atingiu R$ 120.000 de lucro líquido. As cotas foram creditadas conforme a hierarquia. Dinheiro primeiro, sempre.",
        pinned: true
      },
      {
        id: "ann_2",
        author: "DG",
        role: "Founder",
        date: "2026-10-16 19:15",
        title: "ACESSO RESTRITO - NOVO SISTEMA DE PIN 6 DÍGITOS",
        content: "A partir de agora o acesso ao dashboard é exclusivo com autenticação de PIN numérico de 6 dígitos. Não repassem seus PINs para ninguém fora da Nzi.",
        pinned: true
      }
    ],
    transactions: [
      { id: "tx_1", type: "IN", amount: 65000, description: "Liquidação Operação Caixa Rápido", date: "2026-10-16 21:00", author: "Ph Labubu" },
      { id: "tx_2", type: "IN", amount: 55000, description: "Conversão Cripto / Entrada", date: "2026-10-16 18:30", author: "DG" },
      { id: "tx_3", type: "OUT", amount: 48000, description: "Distribuição Semanal - Nível 1 (Owner: Ph Labubu)", date: "2026-10-16 23:45", author: "Sistema" },
      { id: "tx_4", type: "OUT", amount: 30000, description: "Distribuição Semanal - Nível 2 (Founder: DG)", date: "2026-10-16 23:45", author: "Sistema" },
      { id: "tx_5", type: "OUT", amount: 18000, description: "Distribuição Semanal - Nível 3 (Posses: God & Fact)", date: "2026-10-16 23:45", author: "Sistema" },
      { id: "tx_6", type: "OUT", amount: 24000, description: "Distribuição Semanal - Nível 4 (Membros: Anny, Havoc, Necro, SyS, Kage)", date: "2026-10-16 23:45", author: "Sistema" }
    ],
    auditLogs: [
      { id: "log_1", member: "Ph Labubu", role: "Owner", action: "LOGIN", status: "SUCESSO", ip: "10.13.37.1", timestamp: "2026-10-17 01:20:00" },
      { id: "log_2", member: "DG", role: "Founder", action: "LOGIN", status: "SUCESSO", ip: "10.13.37.4", timestamp: "2026-10-17 01:25:30" }
    ],
    members: members,
    posts: getInitialPosts(),
    events: getInitialEvents(),
    links: getInitialLinks(),
    discordAccounts: getInitialDiscordAccounts(),
    panelAccounts: []
  };
}

function getTonightAt23() {
  const d = new Date();
  d.setHours(23, 0, 0, 0);
  if (d.getTime() < Date.now() - 3600000) {
    d.setDate(d.getDate() + 1);
  }
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T23:00`;
}

function getInitialPosts() {
  return [
    {
      id: "post_2",
      title: "Painel Central - Gestão & Monitoramento Operacional",
      description: "O novo Painel da NZI foi atualizado para fornecer visão integrada dos módulos da organização.\n\nRecursos disponíveis:\n- Métricas em tempo real do sistema\n- Gestão de publicações divididas por categoria\n- Temporizadores regressivos sincronizados com o servidor\n- Armazenamento com criptografia AES-256 no banco de dados persistente.\n\nConfigurações adicionais podem ser ajustadas diretamente na aba de Operações pela diretoria.",
      category: "Painel",
      status: "Publicado",
      image: "",
      link: "/dashboard",
      publishedAt: "2026-10-17 01:00",
      createdAt: "2026-10-17 01:00",
      updatedAt: "2026-10-17 01:00",
      author: "DG"
    },
    {
      id: "post_3",
      title: "Segurança de Acessos & Bots Oficiais Discord",
      description: "Todas as integrações do Discord operam com proteção estrita no servidor.\n\n- Credenciais, tokens e webhooks protegidos contra consultas não autorizadas\n- Exibição pública restrita a informações institucionais\n- Histórico de auditoria com IP e registro de quem acessou.",
      category: "Conta Discord",
      status: "Publicado",
      image: "",
      link: "",
      publishedAt: "2026-10-17 02:00",
      createdAt: "2026-10-17 02:00",
      updatedAt: "2026-10-17 02:00",
      author: "Ph Labubu"
    },
    {
      id: "post_4",
      title: "Central de Links Oficiais - Segurança & Protocolos",
      description: "Mantenha-se conectado aos canais oficiais da NZI Mafia através dos nossos 4 pilares: Root, Discord, Telegram e TikTok.\n\nTodos os links passam por validação de protocolo seguro HTTPS e podem ser editados em tempo real pelo painel de Operações.",
      category: "Central de Links",
      status: "Publicado",
      image: "",
      link: "",
      publishedAt: "2026-10-17 03:00",
      createdAt: "2026-10-17 03:00",
      updatedAt: "2026-10-17 03:00",
      author: "DG"
    },
    {
      id: "post_5",
      title: "Briefing: Grande Reunião e Alinhamento Estratégico",
      description: "Publicação informativa sobre o próximo evento agendado da organização.\n\nAcompanhe a contagem regressiva oficial na página de Eventos para participar no horário exato de abertura das salas de conferência.",
      category: "Eventos",
      status: "Publicado",
      image: "",
      link: "",
      publishedAt: "2026-10-17 04:00",
      createdAt: "2026-10-17 04:00",
      updatedAt: "2026-10-17 04:00",
      author: "Ph Labubu"
    }
  ];
}

function getInitialEvents() {
  const tonight = getTonightAt23();
  const dTomorrow = new Date();
  dTomorrow.setDate(dTomorrow.getDate() + 1);
  const pad = n => String(n).padStart(2, '0');
  const tomorrow = `${dTomorrow.getFullYear()}-${pad(dTomorrow.getMonth() + 1)}-${pad(dTomorrow.getDate())}T21:00`;

  return [
    {
      id: "evt_1",
      title: "Evento Confirmado",
      description: "Reunião executiva da liderança com acompanhamento do temporizador regressivo oficial. Apresentação das diretrizes e metas da semana.",
      eventDate: tonight,
      timezone: "America/Sao_Paulo (GMT-3)",
      startTime: "23:00",
      endTime: "01:00",
      status: "Confirmado",
      published: true,
      createdAt: "2026-10-17 04:00",
      updatedAt: "2026-10-17 04:00"
    },
    {
      id: "evt_2",
      title: "Operação Noturna de Alinhamento",
      description: "Coordenação estratégica das equipes e verificação de recursos no servidor.",
      eventDate: tomorrow,
      timezone: "America/Sao_Paulo (GMT-3)",
      startTime: "21:00",
      endTime: "23:30",
      status: "Agendado",
      published: true,
      createdAt: "2026-10-17 04:10",
      updatedAt: "2026-10-17 04:10"
    },
    {
      id: "evt_3",
      title: "Sessão Aberta de Debate e Dúvidas",
      description: "Canal aberto para membros interagirem com a liderança no Discord oficial.",
      eventDate: "2026-10-16T19:00",
      timezone: "America/Sao_Paulo (GMT-3)",
      startTime: "19:00",
      endTime: "20:30",
      status: "Em andamento",
      published: true,
      createdAt: "2026-10-16 18:00",
      updatedAt: "2026-10-17 00:00"
    }
  ];
}

function getInitialLinks() {
  return {
    root: {
      key: "root",
      name: "Root",
      icon: "terminal",
      url: "https://root.nzimafia.com",
      description: "Infraestrutura terminal e acesso centralizado ao núcleo da NZI.",
      isAvailable: true
    },
    discord: {
      key: "discord",
      name: "Discord",
      icon: "discord",
      url: "https://discord.gg/m0gshot",
      description: "Servidor oficial da comunidade e comunicados da liderança.",
      isAvailable: true
    },
    telegram: {
      key: "telegram",
      name: "Telegram",
      icon: "telegram",
      url: "https://t.me/+Om4I_IjpI6liNmMx",
      description: "Canal rápido e avisos de emergência prioritários.",
      isAvailable: true
    },
    tiktok: {
      key: "tiktok",
      name: "TikTok",
      icon: "tiktok",
      url: "https://www.tiktok.com/@nzimafia",
      description: "Vídeos, clipes e bastidores oficiais da organização.",
      isAvailable: true
    }
  };
}

function getInitialDiscordAccounts() {
  return [
    {
      id: "disc_1",
      title: "Bot Moderador NZI Guard",
      botTag: "NZIGuard#0001",
      description: "Bot oficial responsável pela verificação de acessos, moderação e logs automatizados.",
      permissions: "Administrador, Gerenciar Cargos, Banir Membros, Ver Auditoria",
      status: "Ativo",
      isPublicDisclosed: true,
      configuredViaEnv: true,
      envVar: "DISCORD_BOT_TOKEN",
      encryptedSecret: null,
      secretIv: null,
      secretTag: null,
      createdAt: "2026-10-17 02:00",
      updatedAt: "2026-10-17 02:00"
    },
    {
      id: "disc_2",
      title: "Webhook de Transmissões VIP",
      botTag: "NZI-Broadcast#VIP",
      description: "Canal de envio automatizado de novidades e avisos urgentes nos canais prioritários.",
      permissions: "Enviar Mensagens, Inserir Links, Anexar Arquivos",
      status: "Ativo",
      isPublicDisclosed: true,
      configuredViaEnv: true,
      envVar: "DISCORD_WEBHOOK_URL",
      encryptedSecret: null,
      secretIv: null,
      secretTag: null,
      createdAt: "2026-10-17 03:00",
      updatedAt: "2026-10-17 03:00"
    }
  ];
}

function ensureCollections(data) {
  if (!data || typeof data !== 'object') data = {};
  try {
    if (!Array.isArray(data.members)) data.members = [];
    if (!Array.isArray(data.posts) || data.posts.length === 0) {
      try { data.posts = getInitialPosts(); } catch (_) { data.posts = []; }
    }
    if (!Array.isArray(data.events) || data.events.length === 0) {
      try { data.events = getInitialEvents(); } catch (_) { data.events = []; }
    }
    if (!data.links || typeof data.links !== 'object' || Object.keys(data.links).length === 0) {
      try { data.links = getInitialLinks(); } catch (_) { data.links = {}; }
    }
    if (!Array.isArray(data.discordAccounts) || data.discordAccounts.length === 0) {
      try { data.discordAccounts = getInitialDiscordAccounts(); } catch (_) { data.discordAccounts = []; }
    }
    if (!Array.isArray(data.panelAccounts)) data.panelAccounts = [];
    if (!Array.isArray(data.operations)) data.operations = [];
    if (!Array.isArray(data.announcements)) data.announcements = [];
    if (!Array.isArray(data.transactions)) data.transactions = [];
    if (!Array.isArray(data.auditLogs)) data.auditLogs = [];
    if (!data.financials) data.financials = {};
  } catch (err) {
    console.warn('[DB] ensureCollections:', err.message);
  }
  // Nunca grava em disco no ensure — evita crash no Vercel
  return data;
}

// Cache em memória — no Vercel o disco é read-only e paths de includeFiles variam
let _memoryDb = null;

function initDb() {
  if (_memoryDb) return _memoryDb;

  // 1) Tenta ler database.json de vários caminhos possíveis no Vercel
  const candidates = [
    DB_FILE,
    path.join(__dirname, 'database.json'),
    path.join(process.cwd(), 'database.json'),
    path.join(process.cwd(), 'data', 'database.json'),
    path.join(__dirname, 'data', 'database.json')
  ];

  for (const file of candidates) {
    try {
      if (fs.existsSync(file)) {
        const raw = fs.readFileSync(file, 'utf8');
        const parsed = JSON.parse(raw);
        _memoryDb = ensureCollections(parsed);
        console.log('[DB] Carregado de', file, '— membros:', (_memoryDb.members || []).length);
        return _memoryDb;
      }
    } catch (err) {
      console.warn('[DB] Falha ao ler', file, err.message);
    }
  }

  // 2) Fallback: dados iniciais em memória (PINs 777001…)
  try {
    _memoryDb = getInitialData();
    console.log('[DB] Usando dados iniciais em memória — membros:', (_memoryDb.members || []).length);
  } catch (err) {
    console.error('[DB] getInitialData falhou:', err.message);
    _memoryDb = {
      members: [],
      financials: {},
      operations: [],
      announcements: [],
      transactions: [],
      auditLogs: [],
      posts: [],
      events: [],
      links: {},
      discordAccounts: [],
        panelAccounts: []
    };
  }
  return _memoryDb;
}

function getDb() {
  try {
    return initDb();
  } catch (err) {
    console.error('[DB] getDb fatal:', err.message);
    if (!_memoryDb) {
      _memoryDb = { members: [], financials: {}, operations: [], announcements: [], transactions: [], auditLogs: [], posts: [], events: [], links: {}, discordAccounts: [], panelAccounts: [] };
    }
    return _memoryDb;
  }
}

function saveDb(data) {
  // No Vercel (serverless) o filesystem é somente leitura — não quebra o login
  try {
    if (!fs.existsSync(DB_DIR)) {
      fs.mkdirSync(DB_DIR, { recursive: true });
    }
    const tempFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.warn('[DB] saveDb ignorado (filesystem somente leitura / serverless):', err.message);
  }
}

function findMember(identifier) {
  try {
    const database = getDb();
    if (!identifier || !database || !Array.isArray(database.members)) return null;
    const clean = identifier.toString().trim().toLowerCase();
    return database.members.find(m =>
      (m.id && String(m.id).toLowerCase() === clean) ||
      (m.username && String(m.username).toLowerCase() === clean) ||
      (m.name && String(m.name).toLowerCase() === clean)
    ) || null;
  } catch (err) {
    console.warn('[findMember]', err.message);
    return null;
  }
}

function verifyMemberPin(member, pin) {
  try {
    if (!member || !member.pinHash || !pin) return false;
    return bcrypt.compareSync(String(pin), member.pinHash);
  } catch (err) {
    console.warn('[verifyMemberPin]', err.message);
    return false;
  }
}

function verifyMemberPassword(member, password) {
  try {
    if (!member || !member.passwordHash || !password) return false;
    return bcrypt.compareSync(String(password), member.passwordHash);
  } catch (err) {
    console.warn('[verifyMemberPassword]', err.message);
    return false;
  }
}

function verifyMember2FA(member, code) {
  try {
    return getAuthModule().verifyMember2FA(member, code);
  } catch (err) {
    console.warn('[verifyMember2FA]', err.message);
    return false;
  }
}

function updateMemberPassword(identifier, newPassword) {
  if (!newPassword || newPassword.length < 8) {
    throw new Error("A nova senha deve conter pelo menos 8 caracteres.");
  }
  const db = getDb();
  const clean = String(identifier || '').trim().toLowerCase();
  const index = db.members.findIndex(m => 
    (m.id && m.id.toLowerCase() === clean) || 
    (m.username && m.username.toLowerCase() === clean) ||
    (m.name && m.name.toLowerCase() === clean)
  );
  if (index === -1) {
    throw new Error("Membro não encontrado.");
  }
  const salt = bcrypt.genSaltSync(12);
  db.members[index].passwordHash = bcrypt.hashSync(newPassword, salt);
  saveDb(db);
  return db.members[index];
}

function updateMemberPin(identifier, newPin) {
  if (!/^\d{6}$/.test(newPin)) {
    throw new Error("O PIN deve conter exatamente 6 dígitos numéricos.");
  }
  const db = getDb();
  const index = db.members.findIndex(m => 
    m.id.toLowerCase() === identifier.toLowerCase() || 
    m.username.toLowerCase() === identifier.toLowerCase() ||
    m.name.toLowerCase() === identifier.toLowerCase()
  );
  if (index === -1) {
    throw new Error("Membro não encontrado.");
  }
  const salt = bcrypt.genSaltSync(12);
  db.members[index].pinHash = bcrypt.hashSync(newPin, salt);
  db.members[index].defaultPinHint = undefined;
  saveDb(db);
  syncToSupabase('updateMemberPin', () => supabaseDb.updateMemberPin(identifier, newPin));
  return db.members[index];
}

function normalizeAvatarUrl(url) {
  if (!url || typeof url !== 'string') return null;
  let trimmed = url.trim();
  if (!trimmed) return null;
  const imgurPageMatch = trimmed.match(/^https?:\/\/(?:www\.)?imgur\.com\/([a-zA-Z0-9]+)$/);
  if (imgurPageMatch && !['a', 'gallery', 't'].includes(imgurPageMatch[1])) {
    trimmed = `https://i.imgur.com/${imgurPageMatch[1]}.png`;
  }
  return getAuthModule().sanitizeUrl(trimmed) || null;
}

function updateMemberAvatar(identifier, avatarUrl) {
  const db = getDb();
  const clean = String(identifier || '').trim().toLowerCase();
  const index = db.members.findIndex(m => 
    (m.id && m.id.toLowerCase() === clean) || 
    (m.username && m.username.toLowerCase() === clean) ||
    (m.name && m.name.toLowerCase() === clean)
  );
  if (index === -1) {
    throw new Error("Membro não encontrado.");
  }
  const normalized = normalizeAvatarUrl(avatarUrl);
  db.members[index].avatarUrl = normalized;
  saveDb(db);
  return db.members[index];
}

function recordLogin(username, ip, success = true, action = "LOGIN", hwid = null) {
  try {
    const database = getDb();
    if (!database.members) database.members = [];
    if (!database.auditLogs) database.auditLogs = [];
    const clean = String(username || '').toLowerCase();
    const member = database.members.find(m =>
      (m.username && m.username.toLowerCase() === clean) ||
      (m.name && m.name.toLowerCase() === clean)
    );
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);

    if (member && success) {
      member.lastLogin = timestamp;
      member.status = 'online';
    }

    const logEntry = {
      id: `log_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      member: member ? member.name : username,
      role: member ? member.role : 'DESCONHECIDO',
      action: action,
      status: success ? "SUCESSO" : "BLOQUEADO",
      ip: ip || "127.0.0.1",
      hwid: hwid || null,
      timestamp: timestamp
    };

    database.auditLogs.unshift(logEntry);
    if (database.auditLogs.length > 200) {
      database.auditLogs = database.auditLogs.slice(0, 200);
    }

    saveDb(database);
    syncToSupabase('recordLogin', () => supabaseDb.recordLogin(username, ip, success));
    return logEntry;
  } catch (err) {
    console.warn('[recordLogin]', err.message);
    return null;
  }
}

// ==========================================
// SEGURANÇA: IP LOCK & HWID LOCK
// ==========================================

/**
 * Verifica se o IP é confiável para o membro.
 * Retorna: { allowed: true } ou { allowed: false, reason: '...' }
 */
function checkMemberIp(member, ip) {
  if (!member) return { allowed: false, reason: 'Membro não encontrado.' };
  // Se não tem IP registrado ainda, permite (primeiro login)
  if (!member.trustedIp) return { allowed: true, firstTime: true };
  const cleanIp = (ip || '').split(',')[0].trim();
  // Trata equivalência entre loopback IPv4 e IPv6
  const isLoopbackReq = cleanIp === '127.0.0.1' || cleanIp === '::1';
  const isLoopbackTrusted = member.trustedIp === '127.0.0.1' || member.trustedIp === '::1';
  if (isLoopbackReq && isLoopbackTrusted) return { allowed: true };

  if (member.trustedIp === cleanIp) return { allowed: true };
  return {
    allowed: false,
    reason: `IP não autorizado detectado: ${cleanIp}. Acesso bloqueado por segurança.`
  };
}

/**
 * Verifica se o HWID (fingerprint do dispositivo) é confiável.
 */
function checkMemberHwid(member, hwid) {
  if (!member) return { allowed: false, reason: 'Membro não encontrado.' };
  if (!hwid) return { allowed: true }; // sem hwid = ignora (cliente antigo)
  if (!member.trustedHwid) return { allowed: true, firstTime: true };
  if (member.trustedHwid === hwid) return { allowed: true };
  return {
    allowed: false,
    reason: `Dispositivo não autorizado detectado. Acesso bloqueado por segurança.`
  };
}

/**
 * Define o IP confiável de um membro (chamado no primeiro login ou ao resetar).
 */
function setTrustedIp(identifier, ip) {
  const database = getDb();
  const cleanId = identifier.toString().trim().toLowerCase();
  const index = database.members.findIndex(m =>
    m.id.toLowerCase() === cleanId ||
    m.username.toLowerCase() === cleanId ||
    m.name.toLowerCase() === cleanId
  );
  if (index === -1) throw new Error('Membro não encontrado.');
  const cleanIp = (ip || '').split(',')[0].trim();
  database.members[index].trustedIp = cleanIp;
  saveDb(database);
  return database.members[index];
}

/**
 * Define o HWID confiável de um membro.
 */
function setTrustedHwid(identifier, hwid) {
  const database = getDb();
  const cleanId = identifier.toString().trim().toLowerCase();
  const index = database.members.findIndex(m =>
    m.id.toLowerCase() === cleanId ||
    m.username.toLowerCase() === cleanId ||
    m.name.toLowerCase() === cleanId
  );
  if (index === -1) throw new Error('Membro não encontrado.');
  database.members[index].trustedHwid = hwid || null;
  saveDb(database);
  return database.members[index];
}

/**
 * Reseta IP e HWID de um membro (admin pode chamar para permitir novo login de local diferente).
 */
function resetMemberSecurity(identifier) {
  const database = getDb();
  const cleanId = identifier.toString().trim().toLowerCase();
  const index = database.members.findIndex(m =>
    m.id.toLowerCase() === cleanId ||
    m.username.toLowerCase() === cleanId ||
    m.name.toLowerCase() === cleanId
  );
  if (index === -1) throw new Error('Membro não encontrado.');
  database.members[index].trustedIp = null;
  database.members[index].trustedHwid = null;
  saveDb(database);
  return database.members[index];
}

function addAnnouncement({ author, role, title, content, pinned = false }) {
  const db = getDb();
  const now = new Date();
  const timestamp = now.toISOString().replace('T', ' ').substring(0, 16);
  const announcement = {
    id: `ann_${Date.now()}`,
    author,
    role,
    date: timestamp,
    title,
    content,
    pinned: Boolean(pinned)
  };
  db.announcements.unshift(announcement);
  saveDb(db);
  syncToSupabase('addAnnouncement', () => supabaseDb.addAnnouncement(announcement));
  return announcement;
}

function addTransaction({ type, amount, description, author }) {
  const db = getDb();
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

  db.transactions.unshift(tx);
  if (tx.type === 'IN') {
    db.financials.totalVault += parsedAmount;
    db.financials.weeklyProfit += parsedAmount;
  } else {
    db.financials.totalVault = Math.max(0, db.financials.totalVault - parsedAmount);
  }

  saveDb(db);
  syncToSupabase('addTransaction', () => supabaseDb.addTransaction(tx));
  return tx;
}

function addOperation({ title, target, leader, priority, description }) {
  const db = getDb();
  const op = {
    id: `op_${Date.now()}`,
    title: title ? title.trim() : "Nova Operação",
    status: "Em andamento",
    target: Number(target) || 50000,
    leader: leader || "Liderança",
    priority: priority || "ALTA",
    description: description ? description.trim() : "Operação financeira interna"
  };
  db.operations.unshift(op);
  saveDb(db);
  syncToSupabase('addOperation', () => supabaseDb.addOperation(op));
  return op;
}

function updateOperation(id, updates) {
  const db = getDb();
  const index = db.operations.findIndex(o => o.id === id);
  if (index === -1) {
    throw new Error("Operação não encontrada.");
  }
  db.operations[index] = { ...db.operations[index], ...updates };
  saveDb(db);
  syncToSupabase('updateOperation', () => supabaseDb.updateOperation(id, updates));
  return db.operations[index];
}

function updateMemberStatus(identifier, newStatus) {
  const db = getDb();
  const clean = identifier.toString().trim().toLowerCase();
  const index = db.members.findIndex(m => 
    m.id.toLowerCase() === clean || 
    m.username.toLowerCase() === clean || 
    m.name.toLowerCase() === clean
  );
  if (index === -1) return null;
  db.members[index].status = newStatus;
  saveDb(db);
  syncToSupabase('updateMemberStatus', () => supabaseDb.updateMemberStatus(identifier, newStatus));
  return db.members[index];
}

// ==========================================
// MÉTODOS PARA PUBLICAÇÕES (POSTS)
// Categorias: CC, Painel, Conta Discord, Central de Links, Eventos
// ==========================================

function getPosts({ category, status, search, includeUnpublished = false } = {}) {
  const db = getDb();
  let list = db.posts || [];

  if (!includeUnpublished) {
    list = list.filter(p => p.status === 'Publicado');
  } else if (status && status !== 'Todos') {
    list = list.filter(p => p.status.toLowerCase() === status.toLowerCase());
  }

  if (category && category !== 'Todos') {
    list = list.filter(p => p.category.toLowerCase() === category.toLowerCase());
  }

  if (search) {
    const q = search.toLowerCase().trim();
    list = list.filter(p => 
      (p.title && p.title.toLowerCase().includes(q)) || 
      (p.description && p.description.toLowerCase().includes(q)) ||
      (p.category && p.category.toLowerCase().includes(q))
    );
  }

  return [...list].sort((a, b) => new Date(b.createdAt || b.publishedAt || 0) - new Date(a.createdAt || a.publishedAt || 0));
}

function getPostById(id) {
  const db = getDb();
  return (db.posts || []).find(p => p.id === id) || null;
}

function addPost({ title, description, category, image, link, status, author }) {
  const db = getDb();
  if (!title || !title.trim()) throw new Error("Título da publicação é obrigatório.");
  if (!description || !description.trim()) throw new Error("Descrição da publicação é obrigatória.");
  
  const validCategories = ["CC", "Painel", "Conta Discord", "Central de Links", "Eventos"];
  const finalCategory = validCategories.find(c => c.toLowerCase() === (category || '').toLowerCase()) || "CC";
  const validStatuses = ["Publicado", "Rascunho", "Despublicado"];
  const finalStatus = validStatuses.find(s => s.toLowerCase() === (status || '').toLowerCase()) || "Publicado";

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);

  const post = {
    id: `post_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    title: title.trim(),
    description: description.trim(),
    category: finalCategory,
    image: image ? image.trim() : "",
    link: link ? link.trim() : "",
    status: finalStatus,
    publishedAt: finalStatus === "Publicado" ? now : null,
    createdAt: now,
    updatedAt: now,
    author: author || "Administrador"
  };

  db.posts.unshift(post);
  saveDb(db);
  syncToSupabase('addPost', () => supabaseDb.addPost(post));
  return post;
}

function updatePost(id, updates) {
  const db = getDb();
  const index = (db.posts || []).findIndex(p => p.id === id);
  if (index === -1) throw new Error("Publicação não encontrada.");

  const current = db.posts[index];
  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);

  const validCategories = ["CC", "Painel", "Conta Discord", "Central de Links", "Eventos"];
  let finalCategory = current.category;
  if (updates.category) {
    finalCategory = validCategories.find(c => c.toLowerCase() === updates.category.toLowerCase()) || current.category;
  }

  const validStatuses = ["Publicado", "Rascunho", "Despublicado"];
  let finalStatus = current.status;
  if (updates.status) {
    finalStatus = validStatuses.find(s => s.toLowerCase() === updates.status.toLowerCase()) || current.status;
  }

  const updated = {
    ...current,
    title: updates.title !== undefined ? updates.title.trim() : current.title,
    description: updates.description !== undefined ? updates.description.trim() : current.description,
    category: finalCategory,
    image: updates.image !== undefined ? updates.image.trim() : current.image,
    link: updates.link !== undefined ? updates.link.trim() : current.link,
    status: finalStatus,
    updatedAt: now
  };

  if (finalStatus === 'Publicado' && !updated.publishedAt) {
    updated.publishedAt = now;
  }

  db.posts[index] = updated;
  saveDb(db);
  syncToSupabase('updatePost', () => supabaseDb.updatePost(id, updates));
  return updated;
}

function deletePost(id) {
  const db = getDb();
  const initialLength = (db.posts || []).length;
  db.posts = (db.posts || []).filter(p => p.id !== id);
  if (db.posts.length === initialLength) throw new Error("Publicação não encontrada para exclusão.");
  saveDb(db);
  syncToSupabase('deletePost', () => supabaseDb.deletePost(id));
  return { success: true, id };
}

function togglePublishPost(id) {
  const db = getDb();
  const post = (db.posts || []).find(p => p.id === id);
  if (!post) throw new Error("Publicação não encontrada.");

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);
  if (post.status === 'Publicado') {
    post.status = 'Despublicado';
  } else {
    post.status = 'Publicado';
    if (!post.publishedAt) post.publishedAt = now;
  }
  post.updatedAt = now;
  saveDb(db);
  syncToSupabase('togglePublishPost', () => supabaseDb.togglePublishPost(id));
  return post;
}

// ==========================================
// MÉTODOS PARA EVENTOS
// Status: Agendado, Confirmado, Em andamento, Finalizado, Cancelado
// ==========================================

function getEvents({ status, search, includeUnpublished = false } = {}) {
  const db = getDb();
  let list = db.events || [];

  if (!includeUnpublished) {
    list = list.filter(e => e.published !== false);
  } else if (status && status !== 'Todos') {
    list = list.filter(e => e.status.toLowerCase() === status.toLowerCase());
  }

  if (status && status !== 'Todos') {
    list = list.filter(e => e.status.toLowerCase() === status.toLowerCase());
  }

  if (search) {
    const q = search.toLowerCase().trim();
    list = list.filter(e => 
      (e.title && e.title.toLowerCase().includes(q)) || 
      (e.description && e.description.toLowerCase().includes(q)) ||
      (e.status && e.status.toLowerCase().includes(q))
    );
  }

  return [...list].sort((a, b) => new Date(a.eventDate || 0) - new Date(b.eventDate || 0));
}

function getEventById(id) {
  const db = getDb();
  return (db.events || []).find(e => e.id === id) || null;
}

function addEvent({ title, description, eventDate, timezone, startTime, endTime, status, published = true }) {
  const db = getDb();
  if (!title || !title.trim()) throw new Error("Título do evento é obrigatório.");
  if (!eventDate) throw new Error("Data e horário do evento são obrigatórios.");

  const validStatuses = ["Agendado", "Confirmado", "Em andamento", "Finalizado", "Cancelado"];
  const finalStatus = validStatuses.find(s => s.toLowerCase() === (status || '').toLowerCase()) || "Confirmado";

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);
  const event = {
    id: `evt_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    title: title.trim(),
    description: description ? description.trim() : "",
    eventDate: eventDate.trim(),
    timezone: timezone ? timezone.trim() : "America/Sao_Paulo (GMT-3)",
    startTime: startTime ? startTime.trim() : (eventDate.includes('T') ? eventDate.split('T')[1] : "20:00"),
    endTime: endTime ? endTime.trim() : "",
    status: finalStatus,
    published: Boolean(published),
    createdAt: now,
    updatedAt: now
  };

  db.events.unshift(event);
  saveDb(db);
  syncToSupabase('addEvent', () => supabaseDb.addEvent(event));
  return event;
}

function updateEvent(id, updates) {
  const db = getDb();
  const index = (db.events || []).findIndex(e => e.id === id);
  if (index === -1) throw new Error("Evento não encontrado.");

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);
  const current = db.events[index];

  const validStatuses = ["Agendado", "Confirmado", "Em andamento", "Finalizado", "Cancelado"];
  let finalStatus = current.status;
  if (updates.status) {
    finalStatus = validStatuses.find(s => s.toLowerCase() === updates.status.toLowerCase()) || current.status;
  }

  db.events[index] = {
    ...current,
    title: updates.title !== undefined ? updates.title.trim() : current.title,
    description: updates.description !== undefined ? updates.description.trim() : current.description,
    eventDate: updates.eventDate !== undefined ? updates.eventDate.trim() : current.eventDate,
    timezone: updates.timezone !== undefined ? updates.timezone.trim() : current.timezone,
    startTime: updates.startTime !== undefined ? updates.startTime.trim() : current.startTime,
    endTime: updates.endTime !== undefined ? updates.endTime.trim() : current.endTime,
    status: finalStatus,
    published: updates.published !== undefined ? Boolean(updates.published) : current.published,
    updatedAt: now
  };

  saveDb(db);
  syncToSupabase('updateEvent', () => supabaseDb.updateEvent(id, updates));
  return db.events[index];
}

function deleteEvent(id) {
  const db = getDb();
  const initialLength = (db.events || []).length;
  db.events = (db.events || []).filter(e => e.id !== id);
  if (db.events.length === initialLength) throw new Error("Evento não encontrado para exclusão.");
  saveDb(db);
  syncToSupabase('deleteEvent', () => supabaseDb.deleteEvent(id));
  return { success: true, id };
}

function togglePublishEvent(id) {
  const db = getDb();
  const event = (db.events || []).find(e => e.id === id);
  if (!event) throw new Error("Evento não encontrado.");
  event.published = !event.published;
  event.updatedAt = new Date().toISOString().replace('T', ' ').substring(0, 16);
  saveDb(db);
  syncToSupabase('togglePublishEvent', () => supabaseDb.togglePublishEvent(id));
  return event;
}

// ==========================================
// MÉTODOS PARA CENTRAL DE LINKS
// 4 Aplicativos: Root, Discord, Telegram, TikTok
// ==========================================

function getLinks() {
  const db = getDb();
  const links = db.links || getInitialLinks();
  return {
    root: { ...links.root, isAvailable: Boolean(links.root && links.root.url && links.root.url.trim()) },
    discord: { ...links.discord, isAvailable: Boolean(links.discord && links.discord.url && links.discord.url.trim()) },
    telegram: { ...links.telegram, isAvailable: Boolean(links.telegram && links.telegram.url && links.telegram.url.trim()) },
    tiktok: { ...links.tiktok, isAvailable: Boolean(links.tiktok && links.tiktok.url && links.tiktok.url.trim()) }
  };
}

function updateLink(appKey, { url, description, name }) {
  const db = getDb();
  if (!db.links) db.links = getInitialLinks();
  if (!db.links[appKey]) throw new Error(`Aplicativo '${appKey}' inválido. Escolha entre: root, discord, telegram, tiktok.`);

  const cleanUrl = url !== undefined ? url.trim() : db.links[appKey].url;
  // Validação estrita de protocolo: https:// ou esquemas autorizados como tg://, discord:// ou vazio para desativar
  if (cleanUrl) {
    const isHttps = cleanUrl.startsWith('https://');
    const isAllowedScheme = cleanUrl.startsWith('discord://') || cleanUrl.startsWith('tg://');
    if (!isHttps && !isAllowedScheme) {
      throw new Error("Protocolo inválido. Por motivos de segurança, são permitidas apenas URLs com protocolo seguro HTTPS (ex: https://...) ou esquemas oficiais autorizados.");
    }
  }

  db.links[appKey] = {
    ...db.links[appKey],
    url: cleanUrl,
    description: description !== undefined ? description.trim() : db.links[appKey].description,
    name: name !== undefined ? name.trim() : db.links[appKey].name,
    isAvailable: Boolean(cleanUrl && cleanUrl.length > 0)
  };

  saveDb(db);
  syncToSupabase('updateLink', () => supabaseDb.updateLink(appKey, { url, description, name }));
  return db.links[appKey];
}

// ==========================================
// MÉTODOS PARA CONTAS DISCORD & CREDENCIAIS SEGURAS
// ==========================================

function getDiscordAccounts(isAdmin = false, currentMember = null) {
  const db = getDb();
  const list = db.discordAccounts || [];

  if (!isAdmin) {
    return list
      .filter(a => {
        // Se a conta for privada e não foi o membro atual que resgatou, oculta
        if (a.isPublicDisclosed === false) {
          if (!currentMember || (a.claimedById !== currentMember.id && a.claimedBy !== currentMember.username)) {
            return false;
          }
        }

        // SISTEMA DE REWARD:
        // Se a conta JÁ FOI REIVINDICADA, ela SOME do dashboard para todos os outros membros!
        // Ela só fica visível para o membro que a reivindicou.
        if (a.claimed) {
          if (currentMember && (a.claimedById === currentMember.id || a.claimedBy === currentMember.username)) {
            return true; // Exclusivo para quem reivindicou
          }
          return false; // Oculta para todos os outros membros e visitantes
        }

        // Se não foi reivindicada, exibe normalmente
        return true;
      })
      .map(a => {
        const isClaimedByMe = Boolean(
          currentMember && (a.claimedById === currentMember.id || a.claimedBy === currentMember.username)
        );
        const isReward = Boolean(a.isReward !== false && a.encryptedSecret);

        return {
          id: a.id,
          title: a.title || a.email || 'Conta Discord',
          email: isClaimedByMe ? (a.email || '') : (a.email ? a.email.replace(/(.{2}).+(@.+)/, '$1***$2') : ''),
          description: a.description,
          status: a.claimed ? 'Reivindicada' : (a.status || 'Ativo'),
          hasCredentials: Boolean(a.encryptedSecret),
          isReward,
          claimed: Boolean(a.claimed),
          isClaimedByMe,
          claimedAt: isClaimedByMe ? a.claimedAt : null,
          claimedBy: isClaimedByMe ? a.claimedBy : null
        };
      });
  }

  // Visualização Admin: exibe todas as contas com status de reward e quem reivindicou
  return list.map(a => {
    const isClaimedByMe = Boolean(
      currentMember && (a.claimedById === currentMember.id || a.claimedBy === currentMember.username)
    );
    return {
      id: a.id,
      title: a.title || a.email || 'Conta Discord',
      email: a.email || '',
      botTag: a.botTag || '',
      description: a.description,
      status: a.claimed ? 'Reivindicada' : (a.status || 'Ativo'),
      isPublicDisclosed: Boolean(a.isPublicDisclosed),
      hasCredentials: Boolean(a.encryptedSecret),
      isReward: Boolean(a.isReward !== false && a.encryptedSecret),
      claimed: Boolean(a.claimed),
      isClaimedByMe,
      claimedBy: a.claimedBy || null,
      claimedById: a.claimedById || null,
      claimedByName: a.claimedByName || null,
      claimedAt: a.claimedAt || null,
      createdAt: a.createdAt,
      updatedAt: a.updatedAt
    };
  });
}

function addDiscordAccount({ title, email, senha, token, description, status, isPublicDisclosed = true, isReward = true }) {
  const db = getDb();
  if (!email || !email.trim()) throw new Error("E-mail da conta Discord é obrigatório.");

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);
  let enc = { encrypted: '', iv: '', tag: '' };
  const payload = {};
  if (senha && senha.trim()) payload.senha = senha.trim();
  if (token && token.trim()) payload.token = token.trim();
  if (Object.keys(payload).length > 0) {
    enc = encryptSecret(JSON.stringify(payload));
  }

  const account = {
    id: `disc_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    title: (title && title.trim()) || email.trim(),
    email: email.trim(),
    description: description ? description.trim() : "",
    status: status || "Ativo",
    isPublicDisclosed: Boolean(isPublicDisclosed),
    isReward: isReward !== undefined ? Boolean(isReward) : Boolean(enc.encrypted),
    claimed: false,
    claimedBy: null,
    claimedById: null,
    claimedByName: null,
    claimedAt: null,
    encryptedSecret: enc.encrypted,
    secretIv: enc.iv,
    secretTag: enc.tag,
    createdAt: now,
    updatedAt: now
  };

  db.discordAccounts.unshift(account);
  saveDb(db);
  return {
    id: account.id,
    title: account.title,
    email: account.email,
    description: account.description,
    status: account.status,
    isPublicDisclosed: account.isPublicDisclosed,
    isReward: account.isReward,
    claimed: account.claimed,
    hasCredentials: Boolean(account.encryptedSecret)
  };
}

function updateDiscordAccount(id, updates) {
  const db = getDb();
  const index = (db.discordAccounts || []).findIndex(a => a.id === id);
  if (index === -1) throw new Error("Conta Discord não encontrada.");

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);
  const current = db.discordAccounts[index];

  let encFields = {};
  if (updates.senha !== undefined || updates.token !== undefined) {
    let existing = {};
    if (current.encryptedSecret) {
      try {
        existing = JSON.parse(decryptSecret(current.encryptedSecret, current.secretIv, current.secretTag) || '{}');
      } catch (_) {}
    }
    if (updates.senha !== undefined && updates.senha.trim()) existing.senha = updates.senha.trim();
    if (updates.token !== undefined && updates.token.trim()) existing.token = updates.token.trim();
    if (Object.keys(existing).length > 0) {
      const enc = encryptSecret(JSON.stringify(existing));
      encFields = { encryptedSecret: enc.encrypted, secretIv: enc.iv, secretTag: enc.tag };
    }
  }

  const { senha, token, ...safeUpdates } = updates;
  db.discordAccounts[index] = {
    ...current,
    ...safeUpdates,
    ...encFields,
    isReward: safeUpdates.isReward !== undefined ? Boolean(safeUpdates.isReward) : (current.isReward !== undefined ? current.isReward : true),
    title: (safeUpdates.title && safeUpdates.title.trim()) || current.title || current.email,
    updatedAt: now
  };

  saveDb(db);
  const a = db.discordAccounts[index];
  return {
    id: a.id,
    title: a.title,
    email: a.email,
    description: a.description,
    status: a.status,
    isPublicDisclosed: a.isPublicDisclosed,
    isReward: a.isReward,
    claimed: a.claimed,
    hasCredentials: Boolean(a.encryptedSecret)
  };
}

function deleteDiscordAccount(id) {
  const db = getDb();
  const initialLength = (db.discordAccounts || []).length;
  db.discordAccounts = (db.discordAccounts || []).filter(a => a.id !== id);
  if (db.discordAccounts.length === initialLength) throw new Error("Conta Discord não encontrada para exclusão.");
  saveDb(db);
  return { success: true, id };
}

function claimDiscordAccount(id, member, ip) {
  const db = getDb();
  if (!member || !member.username) {
    throw new Error("Você precisa estar autenticado como integrante para reivindicar esta conta.");
  }

  const account = (db.discordAccounts || []).find(a => a.id === id);
  if (!account) {
    throw new Error("Conta Discord não encontrada.");
  }

  if (account.claimed) {
    if (account.claimedById === member.id || account.claimedBy === member.username) {
      throw new Error("Você já reivindicou esta conta anteriormente.");
    }
    throw new Error("Esta conta já foi reivindicada por outro integrante e não está mais disponível.");
  }

  if (!account.encryptedSecret) {
    throw new Error("Esta conta não possui credenciais cadastradas para resgate.");
  }

  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  account.claimed = true;
  account.claimedBy = member.username;
  account.claimedById = member.id;
  account.claimedByName = member.name || member.username;
  account.claimedAt = now;
  account.updatedAt = now;

  const log = {
    id: `log_claim_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    member: member.name || member.username,
    role: member.role || 'Member',
    action: `RECOMPENSA_RESGATADA_DISCORD: ${account.title || account.email} por @${member.username}`,
    status: "SUCESSO",
    ip: ip || "127.0.0.1",
    timestamp: now
  };
  db.auditLogs.unshift(log);
  if (db.auditLogs.length > 150) db.auditLogs = db.auditLogs.slice(0, 150);

  saveDb(db);

  const decrypted = decryptSecret(account.encryptedSecret, account.secretIv, account.secretTag);
  let parsed = { raw: decrypted };
  try { parsed = JSON.parse(decrypted); } catch (_) {}

  return {
    success: true,
    message: `Parabéns, ${member.name || member.username}! Você reivindicou a conta '${account.title || account.email}' com sucesso. As credenciais agora são exclusivas suas e a conta sumiu do dashboard para os outros membros.`,
    account: {
      id: account.id,
      title: account.title,
      email: account.email,
      claimedAt: account.claimedAt,
      credentials: {
        email: account.email,
        senha: parsed.senha || '',
        token: parsed.token || '',
        raw: parsed.raw || ''
      }
    }
  };
}

function getClaimedCredentials(id, member) {
  const db = getDb();
  if (!member) {
    throw new Error("Autenticação necessária.");
  }

  const account = (db.discordAccounts || []).find(a => a.id === id);
  if (!account) {
    throw new Error("Conta Discord não encontrada.");
  }

  if (!account.claimed) {
    throw new Error("Esta conta ainda não foi reivindicada.");
  }

  const isOwnerOfClaim = (account.claimedById === member.id || account.claimedBy === member.username);
  const isAdmin = (member.level && member.level <= 2);

  if (!isOwnerOfClaim && !isAdmin) {
    throw new Error("Acesso restrito: esta credencial é exclusiva do integrante que a reivindicou.");
  }

  if (!account.encryptedSecret) {
    throw new Error("Nenhuma credencial armazenada nesta conta.");
  }

  const decrypted = decryptSecret(account.encryptedSecret, account.secretIv, account.secretTag);
  let parsed = { raw: decrypted };
  try { parsed = JSON.parse(decrypted); } catch (_) {}

  return {
    id: account.id,
    title: account.title,
    email: account.email,
    claimedAt: account.claimedAt,
    claimedBy: account.claimedBy,
    credentials: {
      email: account.email,
      senha: parsed.senha || '',
      token: parsed.token || '',
      raw: parsed.raw || ''
    }
  };
}

function resetDiscordClaim(id, adminMember, ip) {
  const db = getDb();
  const account = (db.discordAccounts || []).find(a => a.id === id);
  if (!account) throw new Error("Conta Discord não encontrada.");

  const prevClaimant = account.claimedBy || 'desconhecido';
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

  account.claimed = false;
  account.claimedBy = null;
  account.claimedById = null;
  account.claimedByName = null;
  account.claimedAt = null;
  account.updatedAt = now;

  const log = {
    id: `log_resclaim_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    member: adminMember ? adminMember.name : "Admin",
    role: adminMember ? adminMember.role : "Owner",
    action: `RESET_CLAIM_DISCORD: ${account.title || account.email} (anteriormente resgatada por @${prevClaimant})`,
    status: "SUCESSO",
    ip: ip || "127.0.0.1",
    timestamp: now
  };
  db.auditLogs.unshift(log);
  if (db.auditLogs.length > 150) db.auditLogs = db.auditLogs.slice(0, 150);

  saveDb(db);
  return {
    success: true,
    message: `Recompensa '${account.title || account.email}' liberada novamente para os membros!`
  };
}

function revealDiscordSecret(id, adminMember, ip) {
  const db = getDb();
  const account = (db.discordAccounts || []).find(a => a.id === id);
  if (!account) throw new Error("Conta Discord não encontrada.");

  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const log = {
    id: `log_sec_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    member: adminMember ? adminMember.name : "Admin",
    role: adminMember ? adminMember.role : "Owner",
    action: `CONSULTA_CREDENCIAIS_DISCORD: ${account.title || account.botTag || id}`,
    status: "SUCESSO",
    ip: ip || "127.0.0.1",
    timestamp: now
  };
  db.auditLogs.unshift(log);
  if (db.auditLogs.length > 150) db.auditLogs = db.auditLogs.slice(0, 150);
  saveDb(db);

  // 1. Contas protegidas e isoladas via variáveis de ambiente (Token do bot e Webhook)
  if (account.configuredViaEnv || account.envVar || account.id === 'disc_1' || account.id === 'disc_2') {
    const envKey = account.envVar || (account.id === 'disc_1' ? 'DISCORD_BOT_TOKEN' : 'DISCORD_WEBHOOK_URL');
    const envVal = (process.env[envKey] || (account.id === 'disc_1' ? process.env.GUARD_NZI_BOT_TOKEN : null) || '').trim();
    if (envVal) {
      return {
        secret: { token: envVal, isConfigured: true },
        title: account.title,
        configuredViaEnv: true,
        envVar: envKey
      };
    }
    return {
      secret: {
        notice: `Token protegido em variáveis de ambiente. Defina a variável ${envKey} no painel da Vercel para uso em produção.`,
        isConfigured: false
      },
      title: account.title,
      configuredViaEnv: true,
      envVar: envKey
    };
  }

  // 2. Contas com segredo criptografado específico
  if (!account.encryptedSecret) {
    throw new Error("Esta conta não possui credencial armazenada.");
  }

  const decrypted = decryptSecret(account.encryptedSecret, account.secretIv, account.secretTag);
  let parsed = { raw: decrypted };
  try { parsed = JSON.parse(decrypted); } catch (_) {}
  return { secret: parsed, title: account.title || account.email, email: account.email };
}

// ==========================================


// ==========================================
// PAINEL ACCOUNTS (user, senha, tipo_login)
// ==========================================

function getPanelAccounts(isAdmin = false) {
  const db = getDb();
  const list = db.panelAccounts || [];
  if (!isAdmin) {
    return list.map(a => ({
      id: a.id,
      label: a.label || a.user || 'Painel',
      user: a.user ? String(a.user).replace(/(.{2}).+/, '$1***') : '',
      tipoLogin: a.tipoLogin,
      status: a.status,
      description: a.description,
      hasCredentials: Boolean(a.encryptedSecret),
      createdAt: a.createdAt
    }));
  }
  return list.map(a => ({
    id: a.id,
    label: a.label || a.user || 'Painel',
    user: a.user,
    tipoLogin: a.tipoLogin,
    status: a.status,
    description: a.description,
    hasCredentials: Boolean(a.encryptedSecret),
    createdAt: a.createdAt,
    updatedAt: a.updatedAt
  }));
}

function addPanelAccount({ user, senha, tipoLogin, label, status, description }) {
  const db = getDb();
  if (!user || !user.trim()) throw new Error("User é obrigatório.");
  if (!senha || !senha.trim()) throw new Error("Senha é obrigatória.");
  if (!tipoLogin || !tipoLogin.trim()) throw new Error("Tipo de login é obrigatório.");

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);
  const enc = encryptSecret(JSON.stringify({ senha: senha.trim() }));

  const account = {
    id: `pnl_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    user: user.trim(),
    tipoLogin: tipoLogin.trim(),
    label: (label && label.trim()) || user.trim(),
    status: status || 'Ativo',
    description: description ? description.trim() : '',
    encryptedSecret: enc.encrypted,
    secretIv: enc.iv,
    secretTag: enc.tag,
    createdAt: now,
    updatedAt: now
  };
  db.panelAccounts.unshift(account);
  saveDb(db);
  return { id: account.id, label: account.label, user: account.user, tipoLogin: account.tipoLogin, status: account.status, hasCredentials: true, createdAt: account.createdAt };
}

function updatePanelAccount(id, updates) {
  const db = getDb();
  const index = (db.panelAccounts || []).findIndex(a => a.id === id);
  if (index === -1) throw new Error("Painel não encontrado.");
  const current = db.panelAccounts[index];
  const now = new Date().toISOString().replace('T', ' ').substring(0, 16);

  let encFields = {};
  if (updates.senha !== undefined && updates.senha.trim()) {
    const enc = encryptSecret(JSON.stringify({ senha: updates.senha.trim() }));
    encFields = { encryptedSecret: enc.encrypted, secretIv: enc.iv, secretTag: enc.tag };
  }

  const { senha, ...safe } = updates;
  db.panelAccounts[index] = { ...current, ...safe, ...encFields, updatedAt: now };
  saveDb(db);
  const a = db.panelAccounts[index];
  return { id: a.id, label: a.label, user: a.user, tipoLogin: a.tipoLogin, status: a.status, hasCredentials: Boolean(a.encryptedSecret), createdAt: a.createdAt };
}

function deletePanelAccount(id) {
  const db = getDb();
  const len = (db.panelAccounts || []).length;
  db.panelAccounts = (db.panelAccounts || []).filter(a => a.id !== id);
  if (db.panelAccounts.length === len) throw new Error("Painel não encontrado.");
  saveDb(db);
  return { success: true, id };
}

function revealPanelSecret(id, adminMember, ip) {
  const db = getDb();
  const account = (db.panelAccounts || []).find(a => a.id === id);
  if (!account) throw new Error("Painel não encontrado.");
  if (!account.encryptedSecret) throw new Error("Sem credenciais armazenadas.");
  const decrypted = decryptSecret(account.encryptedSecret, account.secretIv, account.secretTag);
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  db.auditLogs.unshift({
    id: `log_sec_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    member: adminMember ? adminMember.name : 'Admin',
    role: adminMember ? adminMember.role : 'Owner',
    action: `CONSULTA_CREDENCIAIS_PAINEL: ${account.label || account.user}`,
    status: 'SUCESSO',
    ip: ip || '127.0.0.1',
    timestamp: now
  });
  if (db.auditLogs.length > 150) db.auditLogs = db.auditLogs.slice(0, 150);
  saveDb(db);
  let parsed = {};
  try { parsed = JSON.parse(decrypted); } catch (_) { parsed = { raw: decrypted }; }
  return { secret: parsed, label: account.label, user: account.user, tipoLogin: account.tipoLogin };
}

// ==========================================
// ESTATÍSTICAS REAIS DO DASHBOARD
// ==========================================

function getDashboardStats() {
  const db = getDb();
  const publishedPosts = (db.posts || []).filter(p => p.status === 'Publicado');
  
  const postsByCategory = {
    "Painel": (db.panelAccounts || []).length,
    "Conta Discord": (db.discordAccounts || []).length,
    "Central de Links": 0,
    "Eventos": 0
  };

  publishedPosts.forEach(p => {
    if (p.category === 'Central de Links' || p.category === 'Eventos') {
      if (postsByCategory[p.category] !== undefined) postsByCategory[p.category]++;
    }
  });

  const allEvents = (db.events || []).filter(e => e.published !== false);
  const activeEventsCount = allEvents.filter(e => e.status === 'Em andamento').length;
  const confirmedEventsCount = allEvents.filter(e => e.status === 'Confirmado').length;
  const scheduledEventsCount = allEvents.filter(e => e.status === 'Agendado').length;
  const finishedEventsCount = allEvents.filter(e => e.status === 'Finalizado').length;

  const latestPosts = [...publishedPosts]
    .sort((a, b) => new Date(b.createdAt || b.publishedAt || 0) - new Date(a.createdAt || a.publishedAt || 0))
    .slice(0, 6);

  const links = db.links || {};
  const availableLinksCount = Object.values(links).filter(l => l.url && l.url.trim().length > 0).length;

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
    discordAccountsCount: (db.discordAccounts || []).length
  };
}

// ==========================================
// CADASTRO DE NOVO MEMBRO / ADMINISTRADOR
// ==========================================

function addMember({ username, name, role, level, pin, password, twoFactorSecret }) {
  if (!username || !username.trim()) throw new Error("Codinome de usuário é obrigatório.");
  const cleanUser = username.trim().toLowerCase();
  const db = getDb();
  const existing = findMember(cleanUser);
  if (existing) throw new Error("Já existe um integrante cadastrado com este codinome.");

  const salt = bcrypt.genSaltSync(12);
  const pinCode = pin ? String(pin).trim() : String(Math.floor(100000 + Math.random() * 900000));
  if (!/^\d{6}$/.test(pinCode)) {
    throw new Error("O PIN deve conter exatamente 6 dígitos numéricos.");
  }
  const pinHash = bcrypt.hashSync(pinCode, salt);

  const rawPassword = password ? String(password).trim() : crypto.randomBytes(8).toString('hex') + '!Aa1';
  if (rawPassword.length < 8) {
    throw new Error("A senha deve conter no mínimo 8 caracteres.");
  }
  const passwordHash = bcrypt.hashSync(rawPassword, salt);
  const totpSecret = twoFactorSecret || getAuthModule().generateTotpSecret();
  const numLevel = Number(level) || 4;

  const member = {
    id: `mem_${Date.now()}`,
    username: cleanUser,
    name: name ? name.trim() : username.trim(),
    role: role || (numLevel === 1 ? "Owner" : (numLevel === 2 ? "Founder" : (numLevel === 3 ? "Posse" : "Member"))),
    level: numLevel,
    passwordHash,
    pinHash,
    twoFactorSecret: totpSecret,
    status: "online",
    profitShare: numLevel === 1 ? "40%" : (numLevel === 2 ? "25%" : (numLevel === 3 ? "7.5%" : "4%")),
    weeklyEarnings: numLevel === 1 ? 48000 : (numLevel === 2 ? 30000 : (numLevel === 3 ? 9000 : 4800)),
    createdAt: new Date().toISOString()
  };

  db.members.push(member);
  saveDb(db);
  syncToSupabase('addMember', () => supabaseDb.addMember({ username, name, role, level, pin: pinCode, passwordHash }));
  return member;
}

module.exports = {
  getDb,
  saveDb,
  findMember,
  verifyMemberPin,
  verifyMemberPassword,
  verifyMember2FA,
  updateMemberPin,
  updateMemberPassword,
  recordLogin,
  checkMemberIp,
  checkMemberHwid,
  setTrustedIp,
  setTrustedHwid,
  resetMemberSecurity,
  addAnnouncement,
  addTransaction,
  addOperation,
  updateOperation,
  updateMemberStatus,
  INITIAL_MEMBERS,
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
  // Central de Links
  getLinks,
  updateLink,
  // Contas Discord & Sistema de Reward
  getDiscordAccounts,
  addDiscordAccount,
  updateDiscordAccount,
  deleteDiscordAccount,
  revealDiscordSecret,
  claimDiscordAccount,
  getClaimedCredentials,
  resetDiscordClaim,
  // Panel Accounts
  getPanelAccounts,
  addPanelAccount,
  updatePanelAccount,
  deletePanelAccount,
  revealPanelSecret,
  // Estatísticas & Usuários
  getDashboardStats,
  addMember,
  updateMemberAvatar,
  normalizeAvatarUrl,
  encryptSecret,
  decryptSecret,
  // Supabase Integration
  supabaseDb,
  supabaseClient,
  syncFromSupabase,
  isSupabaseConfigured: supabaseClient.isSupabaseConfigured,
  testSupabaseConnection: supabaseClient.testSupabaseConnection
};
