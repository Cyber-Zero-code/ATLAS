import React, { useState } from 'react';
import { supabase } from '../lib/supabase';
import { Shield, Lock, Mail, ArrowRight, AlertOctagon, LogIn, KeyRound } from 'lucide-react';

interface AuthScreenProps {
  onAuthSuccess: () => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthSuccess }) => {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessNotice(null);
    setIsLoading(true);

    try {
      if (mode === 'signin') {
        const { error } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });

        if (error) {
          throw error;
        }

        onAuthSuccess();
      } else {
        // Self-registration is intentionally not offered: accounts are created by an administrator.
        throw new Error('Self-registration is disabled. Ask your administrator to create your account.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 antialiased">
      <div className="max-w-md w-full space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-950/80 border border-cyan-800 rounded-full text-xs font-mono text-cyan-300 font-bold uppercase tracking-wider">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            Project ATLAS &middot; Stage 1
          </div>
          <h1 className="text-2xl font-bold text-slate-100">
            {mode === 'signin' ? 'Sign In to Workspace' : 'Create User Account'}
          </h1>
          <p className="text-xs text-slate-400">
            Authorised access to cyber-physical risk intelligence. Database-enforced tenancy and TOTP MFA.
          </p>
        </div>

        {/* Auth Box */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl space-y-5">
          {/* Tabs */}
          <div className="grid grid-cols-1 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs font-medium">
            <button
              type="button"
              onClick={() => { setMode('signin'); setErrorMessage(null); setSuccessNotice(null); }}
              className={`py-1.5 rounded transition cursor-pointer flex items-center justify-center gap-1.5 ${
                mode === 'signin' ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LogIn className="w-3.5 h-3.5" />
              Sign In
            </button>
          </div>

          {/* Messages */}
          {errorMessage && (
            <div className="p-3 bg-rose-950/80 border border-rose-800 text-rose-200 rounded-lg text-xs flex items-start gap-2.5">
              <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{errorMessage}</div>
            </div>
          )}

          {successNotice && (
            <div className="p-3 bg-emerald-950/80 border border-emerald-800 text-emerald-200 rounded-lg text-xs leading-relaxed">
              {successNotice}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-cyan-400" />
                Email Address
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@aegis-advisory.test"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                Password
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 px-4 bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 disabled:opacity-50 text-slate-950 font-bold rounded-lg text-xs transition cursor-pointer flex items-center justify-center gap-2 shadow-lg shadow-cyan-950"
            >
              {isLoading ? (
                <span>Authenticating with Supabase...</span>
              ) : (
                <>
                  <span>{mode === 'signin' ? 'Sign In & Verify MFA' : 'Create Account'}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {/* Hard Rule Notice */}
          <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-400 space-y-1">
            <div className="flex items-center gap-1 text-slate-300 font-medium">
              <KeyRound className="w-3 h-3 text-cyan-400" />
              <span>Database-Authoritative Access Control:</span>
            </div>
            <p>
              Users must hold a valid row in <code className="text-slate-300 font-mono">public.memberships</code> to open a client or firm workspace. Client-side persona switching is prohibited.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
