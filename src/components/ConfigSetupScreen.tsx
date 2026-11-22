import React, { useState, useEffect } from 'react';
import { Shield, Key, Database, CheckCircle2, AlertOctagon, Terminal, RefreshCw, Cpu } from 'lucide-react';
import { verifyWebCryptoEngine, SHA256_TEST_VECTORS } from '../utils/crypto';

export const ConfigSetupScreen: React.FC = () => {
  const [cryptoTestResult, setCryptoTestResult] = useState<{ passed: boolean; error?: string } | null>(null);
  const [isRunningTest, setIsRunningTest] = useState(false);

  const runCryptoValidation = async () => {
    setIsRunningTest(true);
    const result = await verifyWebCryptoEngine();
    setCryptoTestResult(result);
    setIsRunningTest(false);
  };

  useEffect(() => {
    runCryptoValidation();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 antialiased">
      <div className="max-w-2xl w-full space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-950/80 border border-cyan-800 rounded-full text-xs font-mono text-cyan-300 font-bold uppercase tracking-wider">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            Project ATLAS &middot; Stage 1 Security Gate
          </div>
          <h1 className="text-3xl font-extrabold text-slate-100 tracking-tight">
            Backend Connection Required
          </h1>
          <p className="text-sm text-slate-400 max-w-lg mx-auto">
            Project ATLAS operates exclusively against live Supabase PostgreSQL workspaces and AAL2 MFA sessions, with no mock data, no persona switcher, and no authentication bypass.
          </p>
        </div>

        {/* Required Environment Setup Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2.5 text-cyan-400 font-mono text-xs font-semibold uppercase tracking-wider">
            <Key className="w-4 h-4" />
            1. Configure Client Environment (.env)
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Supply your project URL and public anonymous key. Never paste or commit the <code className="text-rose-400 font-mono font-bold">service_role</code> key into client code.
          </p>
          <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3.5 font-mono text-xs text-emerald-300 space-y-1">
            <div><span className="text-slate-500"># Project ATLAS Client Configuration</span></div>
            <div>VITE_SUPABASE_URL="https://your-project.supabase.co"</div>
            <div>VITE_SUPABASE_ANON_KEY="your-public-anon-key-here"</div>
          </div>
        </div>

        {/* Migration Run Order Checklist */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2.5 text-cyan-400 font-mono text-xs font-semibold uppercase tracking-wider">
            <Database className="w-4 h-4" />
            2. Run Migrations in Supabase SQL Editor
          </div>
          <p className="text-xs text-slate-300">
            Paste and run all SQL migration scripts in <code className="text-slate-200 font-mono">supabase/migrations/</code> in numeric order (001 through 018):
          </p>
          <ul className="space-y-2 text-xs font-mono text-slate-300">
            <li className="flex items-center gap-2 p-2 bg-slate-950/60 rounded border border-slate-800">
              <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-300 flex items-center justify-center font-bold text-[10px]">1</span>
              <span>supabase/migrations/001_schema_and_extensions.sql</span>
            </li>
            <li className="flex items-center gap-2 p-2 bg-slate-950/60 rounded border border-slate-800">
              <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-300 flex items-center justify-center font-bold text-[10px]">2</span>
              <span>supabase/migrations/002_rls_policies_and_roles.sql</span>
            </li>
            <li className="flex items-center gap-2 p-2 bg-slate-950/60 rounded border border-slate-800">
              <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-300 flex items-center justify-center font-bold text-[10px]">3</span>
              <span>supabase/migrations/003_audit.sql (then 003b_fix_core_function_names.sql)</span>
            </li>
            <li className="flex items-center gap-2 p-2 bg-slate-950/60 rounded border border-slate-800">
              <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-300 flex items-center justify-center font-bold text-[10px]">4</span>
              <span>supabase/migrations/004_storage.sql</span>
            </li>
            <li className="flex items-center gap-2 p-2 bg-slate-950/60 rounded border border-slate-800">
              <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-300 flex items-center justify-center font-bold text-[10px]">5</span>
              <span>supabase/migrations/005_synthetic_seed.sql (followed by 006 through 018_camera_and_threat_indicators.sql)</span>
            </li>
          </ul>
        </div>

        {/* Web Crypto Engine Validation Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5 text-cyan-400 font-mono text-xs font-semibold uppercase tracking-wider">
              <Cpu className="w-4 h-4" />
              Hard Rule 8: Web Crypto API Status
            </div>
            <button
              onClick={runCryptoValidation}
              disabled={isRunningTest}
              className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1 transition cursor-pointer"
            >
              <RefreshCw className={`w-3 h-3 ${isRunningTest ? 'animate-spin' : ''}`} />
              Re-test Vectors
            </button>
          </div>

          {cryptoTestResult?.passed ? (
            <div className="p-3 bg-emerald-950/70 border border-emerald-800 rounded-lg flex items-center justify-between text-xs text-emerald-200">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Web Crypto (crypto.subtle.digest) verified against {SHA256_TEST_VECTORS.length} NIST test vectors.</span>
              </div>
              <span className="font-mono text-[10px] uppercase font-bold bg-emerald-900 text-emerald-300 px-2 py-0.5 rounded">
                COMPLIANT
              </span>
            </div>
          ) : (
            <div className="p-3 bg-rose-950/70 border border-rose-800 rounded-lg flex items-center gap-2 text-xs text-rose-200">
              <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{cryptoTestResult?.error || 'Validating Web Crypto implementation...'}</span>
            </div>
          )}
        </div>

        {/* Security Harness Notice */}
        <div className="text-center text-xs text-slate-500 font-mono">
          Security Test Harness: <span className="text-slate-400">supabase/tests/security_suite.sql</span> (Execute in Supabase SQL Editor to verify RLS, AAL2, and tenant isolation assertions).
        </div>
      </div>
    </div>
  );
};
