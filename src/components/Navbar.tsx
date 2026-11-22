import React from 'react';
import { Membership } from '../types/atlas';
import { WorkspaceSwitcher } from './WorkspaceSwitcher';
import { ShieldCheck, LogOut, User, Map, UploadCloud, ScrollText, GitFork, Flame, Radio, FileCheck } from 'lucide-react';

export type ScreenTab = 'map' | 'import' | 'dependencies' | 'incidents' | 'blast_radius' | 'timeline' | 'audit';

interface NavbarProps {
  userEmail: string;
  memberships: Membership[];
  activeOrgId: string;
  activeTab: ScreenTab;
  onSelectTab: (tab: ScreenTab) => void;
  onSelectOrg: (orgId: string) => void;
  onSignOut: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  userEmail,
  memberships,
  activeOrgId,
  activeTab,
  onSelectTab,
  onSelectOrg,
  onSignOut,
}) => {
  return (
    <header className="bg-slate-950 border-b border-slate-800 text-slate-100 sticky top-0 z-40 select-none shadow-md">
      <div className="max-w-7xl mx-auto px-6 py-2.5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Brand & Workspace Switcher */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 font-mono font-bold text-sm tracking-wider text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
            PROJECT ATLAS
          </div>

          <span className="text-slate-800 hidden md:inline">|</span>

          {/* Workspace Switcher */}
          {memberships.length > 0 && (
            <WorkspaceSwitcher
              memberships={memberships}
              activeOrgId={activeOrgId}
              onSelectOrg={onSelectOrg}
            />
          )}

          {/* Screen Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <button
              onClick={() => onSelectTab('map')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'map'
                  ? 'bg-slate-800 text-cyan-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Map className="w-3.5 h-3.5" />
              <span>Map</span>
            </button>
            <button
              onClick={() => onSelectTab('import')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'import'
                  ? 'bg-slate-800 text-cyan-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Import</span>
            </button>
            <button
              onClick={() => onSelectTab('dependencies')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'dependencies'
                  ? 'bg-slate-800 text-cyan-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitFork className="w-3.5 h-3.5" />
              <span>Dependencies</span>
            </button>
            <button
              onClick={() => onSelectTab('incidents')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'incidents'
                  ? 'bg-slate-800 text-rose-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Radio className="w-3.5 h-3.5 text-rose-400" />
              <span>Intake</span>
            </button>
            <button
              onClick={() => onSelectTab('blast_radius')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'blast_radius'
                  ? 'bg-slate-800 text-amber-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Flame className="w-3.5 h-3.5 text-amber-400" />
              <span>Blast Radius</span>
            </button>
            <button
              onClick={() => onSelectTab('timeline')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'timeline'
                  ? 'bg-slate-800 text-purple-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCheck className="w-3.5 h-3.5 text-purple-400" />
              <span>Timeline & Evidence</span>
            </button>
            <button
              onClick={() => onSelectTab('audit')}
              className={`px-2 py-1 rounded transition flex items-center gap-1 cursor-pointer ${
                activeTab === 'audit'
                  ? 'bg-slate-800 text-cyan-300 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ScrollText className="w-3.5 h-3.5" />
              <span>Ledger</span>
            </button>
          </nav>
        </div>



        {/* User Session & Status Bar */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="flex items-center gap-1.5 text-slate-300 font-mono">
              <User className="w-3.5 h-3.5 text-slate-500" />
              <span>{userEmail}</span>
            </span>

            <span className="flex items-center gap-1 text-emerald-400 font-mono text-[10px] bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-900/80">
              <ShieldCheck className="w-3 h-3" />
              AAL2 MFA
            </span>
          </div>

          <button
            onClick={onSignOut}
            className="px-2.5 py-1 text-xs bg-slate-900 hover:bg-rose-950/60 text-slate-300 hover:text-rose-300 rounded border border-slate-700 hover:border-rose-800 transition cursor-pointer flex items-center gap-1.5"
            title="Sign out of Supabase Auth"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </div>
    </header>
  );
};

