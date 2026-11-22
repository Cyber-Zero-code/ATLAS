import React from 'react';
import { Membership } from '../types/atlas';
import { Building2, ChevronDown, Check, ShieldAlert, Briefcase } from 'lucide-react';

interface WorkspaceSwitcherProps {
  memberships: Membership[];
  activeOrgId: string;
  onSelectOrg: (orgId: string) => void;
}

export const WorkspaceSwitcher: React.FC<WorkspaceSwitcherProps> = ({
  memberships,
  activeOrgId,
  onSelectOrg,
}) => {
  const activeMembership = memberships.find((m) => m.org_id === activeOrgId) || memberships[0];

  return (
    <div className="relative inline-block text-left">
      <div className="flex items-center gap-2">
        <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1">
          <Briefcase className="w-3.5 h-3.5 text-cyan-400" />
          Workspace:
        </label>
        <select
          value={activeOrgId}
          onChange={(e) => onSelectOrg(e.target.value)}
          className="bg-slate-900 border border-slate-700 text-slate-100 text-xs rounded-lg px-3 py-1.5 font-medium focus:outline-none focus:border-cyan-500 cursor-pointer transition pr-8"
        >
          {memberships.map((m) => {
            const org = m.organization;
            const orgName = org?.name || `Organisation (${m.org_id.substring(0, 8)})`;
            const orgCode = org?.code ? `[${org.code}]` : '';
            const kindLabel = org?.kind ? `(${org.kind.toUpperCase()})` : '';
            return (
              <option key={m.org_id} value={m.org_id} className="bg-slate-950 text-slate-100">
                {orgName} {orgCode} {kindLabel} - {m.role}
              </option>
            );
          })}
        </select>

        {activeMembership && (
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${
              activeMembership.role === 'atlas:admin'
                ? 'bg-purple-950/80 text-purple-300 border-purple-800'
                : 'bg-cyan-950/80 text-cyan-300 border-cyan-800'
            }`}
          >
            {activeMembership.role}
          </span>
        )}
      </div>
    </div>
  );
};
