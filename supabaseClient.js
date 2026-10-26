const { createClient } = require('@supabase/supabase-js');

// Carrega variáveis de ambiente se ainda não carregadas
if (!process.env.SUPABASE_URL) {
  try {
    require('dotenv').config();
  } catch (e) {}
}

const SUPABASE_URL = process.env.SUPABASE_URL || '';
// Prefere a chave de serviço (service_role) para operações completas no back-end,
// ou a chave anônima (anon key) como fallback
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY || '';

let supabase = null;

function isSupabaseConfigured() {
  return Boolean(
    SUPABASE_URL && 
    SUPABASE_URL.trim().length > 0 && 
    SUPABASE_KEY && 
    SUPABASE_KEY.trim().length > 0 &&
    !SUPABASE_URL.includes('seu-projeto')
  );
}

function getSupabase() {
  if (!isSupabaseConfigured()) {
    return null;
  }
  if (!supabase) {
    try {
      supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      });
    } catch (err) {
      console.error('[SUPABASE] Erro ao instanciar cliente Supabase:', err.message);
      return null;
    }
  }
  return supabase;
}

// Testa a conexão ativa com o banco Supabase
async function testSupabaseConnection() {
  const client = getSupabase();
  if (!client) {
    return {
      connected: false,
      configured: false,
      message: 'Supabase não configurado. Defina SUPABASE_URL e SUPABASE_KEY no arquivo .env'
    };
  }

  try {
    // Executa um health check simples consultando a tabela members ou financials
    const { data, error } = await client
      .from('members')
      .select('count', { count: 'exact', head: true });

    if (error) {
      // Se a tabela não existir ainda ou der erro de RLS
      return {
        connected: false,
        configured: true,
        error: error.message,
        message: `Conectou ao host Supabase, mas ocorreu um erro: ${error.message}. Execute o script supabase_schema.sql no SQL Editor do Supabase.`
      };
    }

    return {
      connected: true,
      configured: true,
      message: 'Conexão com banco Supabase estabelecida com sucesso!',
      memberCount: data
    };
  } catch (err) {
    return {
      connected: false,
      configured: true,
      error: err.message,
      message: `Falha ao conectar com o banco Supabase: ${err.message}`
    };
  }
}

module.exports = {
  getSupabase,
  isSupabaseConfigured,
  testSupabaseConnection,
  SUPABASE_URL,
  SUPABASE_KEY
};
