import React, { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';
import { atlasService } from '../data/api';
import { ShieldCheck, KeyRound, QrCode, ArrowRight, AlertOctagon, LogOut, CheckCircle2 } from 'lucide-react';

interface MfaScreenProps {
  onMfaVerified: () => void;
  onSignOut: () => void;
}

export const MfaScreen: React.FC<MfaScreenProps> = ({ onMfaVerified, onSignOut }) => {
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [factorId, setFactorId] = useState<string | null>(null);
  const [qrCodeSvg, setQrCodeSvg] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);

  const initMfaStatus = async () => {
    setIsInitializing(true);
    setErrorMessage(null);
    try {
      const { data, error } = await supabase.auth.mfa.listFactors();
      if (error) throw error;

      const verifiedFactors = data?.totp?.filter((f) => f.status === 'verified') || [];

      if (verifiedFactors.length > 0) {
        // Factor already enrolled: prompt challenge
        setIsEnrolling(false);
        setFactorId(verifiedFactors[0].id);
      } else {
        // Enrol new factor
        setIsEnrolling(true);
        const enrolled = await atlasService.enrollTotpFactor();
        setFactorId(enrolled.id);
        setQrCodeSvg(enrolled.qrCode);
        setSecret(enrolled.secret);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to initialize MFA state.');
    } finally {
      setIsInitializing(false);
    }
  };

  useEffect(() => {
    initMfaStatus();
  }, []);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!factorId) return;

    setIsLoading(true);
    setErrorMessage(null);

    try {
      await atlasService.challengeAndVerifyTotp(factorId, code.trim());
      onMfaVerified();
    } catch (err: any) {
      setErrorMessage(err.message || 'Invalid authentication code. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 antialiased">
      <div className="max-w-md w-full space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-emerald-950/80 border border-emerald-800 rounded-full text-xs font-mono text-emerald-300 font-bold uppercase tracking-wider">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Mandatory AAL2 Two-Factor Authentication
          </div>
          <h1 className="text-2xl font-bold text-slate-100">
            {isEnrolling ? 'Enrol TOTP Authenticator' : 'Two-Factor Verification'}
          </h1>
          <p className="text-xs text-slate-400">
            Project ATLAS enforces Authenticator Assurance Level 2 (AAL2) at the PostgreSQL RLS policy level.
          </p>
        </div>

        {/* Verification Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl space-y-5">
          {errorMessage && (
            <div className="p-3 bg-rose-950/80 border border-rose-800 text-rose-200 rounded-lg text-xs flex items-start gap-2.5">
              <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{errorMessage}</div>
            </div>
          )}

          {isInitializing ? (
            <div className="py-8 text-center text-xs text-slate-400 font-mono">
              Checking authenticator factors...
            </div>
          ) : (
            <>
              {isEnrolling && (
                <div className="space-y-4">
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg flex flex-col items-center justify-center space-y-3">
                    {qrCodeSvg ? (
                      <img
                        className="bg-white p-2 rounded-lg w-48 h-48"
                        alt="Scan with your authenticator app"
                        src={
                          qrCodeSvg.startsWith('data:image/')
                            ? qrCodeSvg
                            : `data:image/svg+xml;utf-8,${encodeURIComponent(qrCodeSvg)}`
                        }
                      />
                    ) : (
                      <QrCode className="w-24 h-24 text-slate-600" />
                    )}
                    <div className="text-center">
                      <div className="text-xs font-medium text-slate-300">
                        Scan QR code with your Authenticator app
                      </div>
                      {secret && (
                        <div className="mt-2 text-[11px] font-mono text-cyan-300 bg-slate-900 px-2 py-1 rounded border border-slate-800 select-all">
                          Secret: {secret}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              <form onSubmit={handleVerify} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
                    6-Digit Security Code
                  </label>
                  <input
                    type="text"
                    required
                    maxLength={6}
                    pattern="\d{6}"
                    autoFocus
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="w-full text-center tracking-widest text-lg font-mono px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading || code.length !== 6}
                  className="w-full py-2.5 px-4 bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 disabled:opacity-50 text-slate-950 font-bold rounded-lg text-xs transition cursor-pointer flex items-center justify-center gap-2 shadow-lg shadow-cyan-950"
                >
                  {isLoading ? (
                    <span>Verifying Code with Supabase...</span>
                  ) : (
                    <>
                      <span>{isEnrolling ? 'Activate & Enter Workspace' : 'Verify & Unlock Workspace'}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </form>
            </>
          )}

          {/* Footer Actions */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
            <button
              onClick={onSignOut}
              className="text-slate-400 hover:text-rose-300 transition flex items-center gap-1.5 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
            <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              MFA Mandated (AAL2)
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
