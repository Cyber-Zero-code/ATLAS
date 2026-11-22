import React, { useState } from 'react';
import { ATLAS_NAV_GROUPS, NavModuleItem } from '../../config/navigation';
import { ModuleGroupId, ModuleId } from '../../types/atlas';
import {
  Command,
  Activity,
  Briefcase,
  Globe,
  Satellite,
  Mountain,
  UploadCloud,
  Crosshair,
  ShieldAlert,
  Radar,
  Radio,
  Bug,
  Network,
  AlertOctagon,
  SearchCode,
  Box,
  Share2,
  GitFork,
  MapPin,
  FileText,
  TrendingUp,
  AlertTriangle,
  BarChart3,
  Bot,
  Cpu,
  Users,
  KeyRound,
  ScrollText,
  Database,
  Settings,
  ChevronDown,
  ChevronRight,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';

interface LeftSidebarProps {
  activeModule: ModuleId;
  onSelectModule: (moduleId: ModuleId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  counts: {
    incidents: number;
    proposedMatches: number;
    assets: number;
  };
}

const ICON_MAP: Record<NavModuleItem['iconName'], React.ComponentType<{ className?: string }>> = {
  Command,
  Activity,
  Briefcase,
  Globe,
  Satellite,
  Mountain,
  UploadCloud,
  Crosshair,
  ShieldAlert,
  Radar,
  Radio,
  Bug,
  Network,
  AlertOctagon,
  SearchCode,
  Box,
  Share2,
  GitFork,
  MapPin,
  FileText,
  TrendingUp,
  AlertTriangle,
  BarChart3,
  Bot,
  Cpu,
  Users,
  KeyRound,
  ScrollText,
  Database,
  Settings,
};

export const LeftSidebar: React.FC<LeftSidebarProps> = ({
  activeModule,
  onSelectModule,
  collapsed,
  onToggleCollapse,
  counts,
}) => {
  const [openGroups, setOpenGroups] = useState<Record<ModuleGroupId, boolean>>({
    command: true,
    geoint: true,
    cyber: true,
    analysis: true,
    ai: true,
    admin: true,
  });

  const toggleGroup = (id: ModuleGroupId) => {
    setOpenGroups((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <aside
      className={`bg-(--atlas-bg-inset) border-r border-(--atlas-border) flex flex-col shrink-0 select-none transition-all duration-150 ${
        collapsed ? 'w-12' : 'w-60'
      }`}
    >
      {/* Sidebar Header / Collapse Toggle */}
      <div className="h-8 px-2.5 border-b border-(--atlas-border) flex items-center justify-between shrink-0">
        {!collapsed && (
          <span className="font-mono text-[10px] tracking-[0.14em] text-(--atlas-text-secondary) font-semibold">
            OPERATIONAL MODULES
          </span>
        )}
        <button
          onClick={onToggleCollapse}
          className="p-1 text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) hover:bg-(--atlas-bg-elevated) rounded-[2px] cursor-pointer ml-auto"
          title={collapsed ? 'Expand Navigation' : 'Collapse Navigation'}
          aria-label={collapsed ? 'Expand Navigation' : 'Collapse Navigation'}
        >
          {collapsed ? <PanelLeftOpen className="w-3.5 h-3.5" /> : <PanelLeftClose className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto py-1.5 space-y-1">
        {ATLAS_NAV_GROUPS.map((group) => {
          const isOpen = openGroups[group.id];
          return (
            <div key={group.id} className="border-b border-(--atlas-bg-elevated) pb-1 last:border-b-0">
              {!collapsed && (
                <button
                  onClick={() => toggleGroup(group.id)}
                  className="w-full px-2.5 py-1.5 flex items-center justify-between text-[10px] font-mono font-semibold tracking-[0.12em] text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) cursor-pointer"
                >
                  <span>{group.title}</span>
                  {isOpen ? (
                    <ChevronDown className="w-3 h-3 text-(--atlas-text-muted)" />
                  ) : (
                    <ChevronRight className="w-3 h-3 text-(--atlas-text-muted)" />
                  )}
                </button>
              )}

              {(collapsed || isOpen) && (
                <div className="space-y-0.5 px-1.5">
                  {group.modules.map((mod) => {
                    const Icon = ICON_MAP[mod.iconName];
                    const isActive = activeModule === mod.id;

                    let rightCounter: number | null = null;
                    if (mod.id === 'cyber_incidents' || mod.id === 'cyber_monitoring') {
                      rightCounter = counts.incidents;
                    } else if (mod.id === 'asset_tracking') {
                      rightCounter = counts.assets;
                    } else if (mod.id === 'threat_intelligence' && counts.proposedMatches > 0) {
                      rightCounter = counts.proposedMatches;
                    }

                    return (
                      <button
                        key={mod.id}
                        onClick={() => onSelectModule(mod.id)}
                        title={collapsed ? `${mod.label} — ${mod.description}` : mod.description}
                        className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-[2px] text-xs transition-colors cursor-pointer border-l-2 ${
                          isActive
                            ? 'bg-(--atlas-accent-olive)/20 text-(--atlas-text-primary) border-l-(--atlas-olive-bright) font-medium'
                            : 'text-(--atlas-text-secondary) hover:text-(--atlas-text-primary) hover:bg-(--atlas-bg-elevated) border-l-transparent'
                        } ${collapsed ? 'justify-center px-0' : ''}`}
                      >
                        <Icon
                          className={`w-3.5 h-3.5 shrink-0 ${
                            isActive ? 'text-(--atlas-olive-bright)' : 'text-(--atlas-text-secondary)'
                          }`}
                        />
                        {!collapsed && (
                          <>
                            <span className="truncate flex-1 text-left">{mod.label}</span>
                            {rightCounter !== null && (
                              <span className="font-mono text-[10px] tabular-nums text-(--atlas-text-secondary)">
                                {rightCounter}
                              </span>
                            )}
                          </>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>
    </aside>
  );
};
