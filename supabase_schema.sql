-- ====================================================================
-- NZI MAFIA — SCHEMA SUPABASE POSTGRESQL & SISTEMA DE LOGIN
-- ====================================================================
-- Execute este script no SQL Editor do seu projeto Supabase:
-- https://supabase.com/dashboard/project/_/sql
-- ====================================================================

-- 1. Habilitar extensões úteis
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ====================================================================
-- 2. CRIAÇÃO DAS TABELAS
-- ====================================================================

-- TABELA: members (Membros da Hierarquia Nzi Mafia com Criptografia de Senha e 2FA)
CREATE TABLE IF NOT EXISTS public.members (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    level INTEGER NOT NULL,
    pin_hash TEXT NOT NULL,
    password_hash TEXT,
    two_factor_secret TEXT,
    status TEXT NOT NULL DEFAULT 'online',
    profit_share TEXT NOT NULL DEFAULT '4%',
    weekly_earnings NUMERIC NOT NULL DEFAULT 0,
    last_login TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: financials (Cofre da Nzi Mafia e Divisão Semanal)
CREATE TABLE IF NOT EXISTS public.financials (
    id INTEGER PRIMARY KEY DEFAULT 1,
    total_vault NUMERIC NOT NULL DEFAULT 1290000,
    weekly_profit NUMERIC NOT NULL DEFAULT 165000,
    currency TEXT NOT NULL DEFAULT 'BRL',
    last_distribution TEXT NOT NULL DEFAULT '2026-10-16 23:45',
    rules JSONB NOT NULL DEFAULT '{
        "level1": "40% (Owner)",
        "level2": "25% (Founder)",
        "level3": "15% total (7.5% por Posse)",
        "level4": "20% total (4% por Membro)"
    }'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT single_financials_row CHECK (id = 1)
);

-- TABELA: operations (Operações em Andamento, Metas e Liderança)
CREATE TABLE IF NOT EXISTS public.operations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Em andamento',
    target NUMERIC NOT NULL DEFAULT 0,
    leader TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'ALTA',
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: announcements (Mural Confidencial da Liderança)
CREATE TABLE IF NOT EXISTS public.announcements (
    id TEXT PRIMARY KEY,
    author TEXT NOT NULL,
    role TEXT NOT NULL,
    date TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: transactions (Livro Caixa e Movimentações do Cofre)
CREATE TABLE IF NOT EXISTS public.transactions (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('IN', 'OUT')),
    amount NUMERIC NOT NULL,
    description TEXT NOT NULL,
    date TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: audit_logs (Auditoria de Logins com PIN, IPs e Ações Críticas)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id TEXT PRIMARY KEY,
    member TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    ip TEXT,
    timestamp TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: posts (Publicações do Dashboard divididas por Categoria: Painel, Conta Discord, etc.)
CREATE TABLE IF NOT EXISTS public.posts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Publicado',
    image TEXT DEFAULT '',
    link TEXT DEFAULT '',
    published_at TEXT,
    author TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: events (Eventos e Temporizadores Regressivos)
CREATE TABLE IF NOT EXISTS public.events (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    event_date TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT 'America/Sao_Paulo (GMT-3)',
    start_time TEXT,
    end_time TEXT,
    status TEXT NOT NULL DEFAULT 'Agendado',
    published BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: links (Central de Links Oficiais dos 4 Canais: Root, Discord, Telegram, TikTok)
CREATE TABLE IF NOT EXISTS public.links (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT NOT NULL,
    url TEXT NOT NULL,
    description TEXT,
    is_available BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TABELA: discord_accounts (Contas Discord & Bots Oficiais com Credenciais Criptografadas)
CREATE TABLE IF NOT EXISTS public.discord_accounts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    bot_tag TEXT,
    description TEXT,
    permissions TEXT,
    status TEXT NOT NULL DEFAULT 'Ativo',
    is_public_disclosed BOOLEAN NOT NULL DEFAULT TRUE,
    encrypted_secret TEXT,
    secret_iv TEXT,
    secret_tag TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);


-- ====================================================================
-- 2.1 ATUALIZAÇÃO DE COLUNAS (versão atual do app) — seguro rodar mais de uma vez
-- ====================================================================
ALTER TABLE public.members ADD COLUMN IF NOT EXISTS default_pin_hint TEXT;
ALTER TABLE public.members ADD COLUMN IF NOT EXISTS trusted_ip TEXT;
ALTER TABLE public.members ADD COLUMN IF NOT EXISTS trusted_hwid TEXT;
ALTER TABLE public.members ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE public.members ADD COLUMN IF NOT EXISTS two_factor_secret TEXT;
ALTER TABLE public.members ALTER COLUMN pin_hash DROP NOT NULL;

ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS hwid TEXT;
ALTER TABLE public.audit_logs ALTER COLUMN role DROP NOT NULL;

ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS is_reward BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS claimed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS claimed_by_id TEXT;
ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS claimed_by_name TEXT;
ALTER TABLE public.discord_accounts ADD COLUMN IF NOT EXISTS claimed_at TEXT;

ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS published_at TEXT;

-- Remove membros antigos do seed anterior (hashes de exemplo, não são os usuários reais)
DELETE FROM public.members WHERE id IN ('mem_1','mem_2','mem_3','mem_4','mem_5','mem_6','mem_7','mem_8','mem_9')
  AND password_hash LIKE '$2b$12$Z0bZ6k7q5gJq4ZzY0xU4eO5vV6f7w8x9y0z1a2b3c4d5e6f7g8h9i';

-- ====================================================================
-- 3. POLÍTICAS DE ROW LEVEL SECURITY (RLS)
-- ====================================================================

-- Habilitar RLS em todas as tabelas
ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.financials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.discord_accounts ENABLE ROW LEVEL SECURITY;

-- Service Role (Backend Node.js com chave service_role) tem acesso total a tudo
DO $$
BEGIN
    -- Dropar políticas antigas se existirem para evitar conflito ao reexecutar
    DROP POLICY IF EXISTS "service_role_members" ON public.members;
    DROP POLICY IF EXISTS "service_role_financials" ON public.financials;
    DROP POLICY IF EXISTS "service_role_operations" ON public.operations;
    DROP POLICY IF EXISTS "service_role_announcements" ON public.announcements;
    DROP POLICY IF EXISTS "service_role_transactions" ON public.transactions;
    DROP POLICY IF EXISTS "service_role_audit_logs" ON public.audit_logs;
    DROP POLICY IF EXISTS "service_role_posts" ON public.posts;
    DROP POLICY IF EXISTS "service_role_events" ON public.events;
    DROP POLICY IF EXISTS "service_role_links" ON public.links;
    DROP POLICY IF EXISTS "service_role_discord_accounts" ON public.discord_accounts;

    -- Políticas públicas de leitura segura
    DROP POLICY IF EXISTS "public_read_published_posts" ON public.posts;
    DROP POLICY IF EXISTS "public_read_published_events" ON public.events;
    DROP POLICY IF EXISTS "public_read_links" ON public.links;
    DROP POLICY IF EXISTS "public_read_discord_accounts" ON public.discord_accounts;
    DROP POLICY IF EXISTS "anon_read_public_members" ON public.members;
END $$;

-- 1. Acesso total para service_role (Backend API)
CREATE POLICY "service_role_members" ON public.members FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_financials" ON public.financials FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_operations" ON public.operations FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_announcements" ON public.announcements FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_transactions" ON public.transactions FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_audit_logs" ON public.audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_posts" ON public.posts FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_events" ON public.events FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_links" ON public.links FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_discord_accounts" ON public.discord_accounts FOR ALL TO service_role USING (true) WITH CHECK (true);

-- 2. SEM políticas para anon/authenticated: o site só acessa o banco pelo servidor
--    (chave service_role). Com RLS ligado e nenhuma política, a chave anon não lê nada.
DO $$
BEGIN
    DROP POLICY IF EXISTS "public_read_published_posts" ON public.posts;
    DROP POLICY IF EXISTS "public_read_published_events" ON public.events;
    DROP POLICY IF EXISTS "public_read_links" ON public.links;
    DROP POLICY IF EXISTS "public_read_discord_accounts" ON public.discord_accounts;
    DROP POLICY IF EXISTS "anon_read_public_members" ON public.members;
END $$;


-- ====================================================================
-- 4. DADOS: sem seed no SQL. Importe seus dados reais com:  npm run supabase:migrate
--    (lê o database.json LOCAL e grava no Supabase; nada de hashes/segredos neste arquivo)
-- ====================================================================
