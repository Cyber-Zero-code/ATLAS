/**
 * Project ATLAS: Supabase Client Configuration
 * 
 * STRICT SECURITY CONSTRAINTS:
 * - Uses ONLY the public anon key (never service_role key!)
 * - Key and URL injected via VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY
 * - Portable plain Postgres + Supabase Auth & Storage
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';

const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
const supabaseUrl = env?.VITE_SUPABASE_URL || '';
const supabaseAnonKey = env?.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = (): boolean => {
  return (
    typeof supabaseUrl === 'string' &&
    supabaseUrl.startsWith('https://') &&
    !supabaseUrl.includes('your-project') &&
    typeof supabaseAnonKey === 'string' &&
    supabaseAnonKey.length > 20 &&
    !supabaseAnonKey.includes('your-public-anon-key')
  );
};

// Singleton Supabase Client
export const supabase: SupabaseClient = createClient(
  isSupabaseConfigured() ? supabaseUrl : 'https://placeholder-project.supabase.co',
  isSupabaseConfigured() ? supabaseAnonKey : 'placeholder-anon-key-atlas-h1-client',
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
    },
  }
);
