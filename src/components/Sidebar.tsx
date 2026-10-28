/**
 * NetScope — Sidebar Navigation Component (Graphite Minimal Theme)
 */

import React from 'react';
import {
  LayoutDashboard,
  Radio,
  Search,
  PieChart,
  TrendingUp,
  History,
  FileUp,
  GraduationCap,
  Settings,
  Info,
  ShieldAlert,
} from 'lucide-react';

export type NavigationTab = 
  | 'overview'
  | 'live-capture'
  | 'explorer'
  | 'protocol-analysis'
  | 'traffic-monitor'
  | 'history'
  | 'pcap-import'
  | 'academic-guide'
  | 'settings'
  | 'about';

interface SidebarProps {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  packetCount: number;
  isCapturing: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  packetCount,
  isCapturing,
}) => {
  const navItems = [
    {
      id: 'overview' as NavigationTab,
      label: 'Overview',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'live-capture' as NavigationTab,
      label: 'Live Packet Capture',
      icon: Radio,
      badge: isCapturing ? 'LIVE' : null,
      badgeColor: 'bg-[#34D399]/15 text-[#34D399] border border-[#34D399]/30',
    },
    {
      id: 'explorer' as NavigationTab,
      label: 'Packet Explorer',
      icon: Search,
      badge: packetCount > 0 ? packetCount.toLocaleString() : null,
      badgeColor: 'bg-[#202429] text-[#94A3B8] border border-[#454B53] font-mono text-[10px]',
    },
    {
      id: 'protocol-analysis' as NavigationTab,
      label: 'Protocol Analysis',
      icon: PieChart,
      badge: null,
    },
    {
      id: 'traffic-monitor' as NavigationTab,
      label: 'Traffic Statistics',
      icon: TrendingUp,
      badge: null,
    },
    {
      id: 'history' as NavigationTab,
      label: 'Capture History',
      icon: History,
      badge: null,
    },
    {
      id: 'pcap-import' as NavigationTab,
      label: 'PCAP Import & Export',
      icon: FileUp,
      badge: 'Wireshark',
      badgeColor: 'bg-[#202429] text-[#60A5FA] text-[10px] border border-[#454B53]',
    },
    {
      id: 'academic-guide' as NavigationTab,
      label: 'Academic & CN Concepts',
      icon: GraduationCap,
      badge: 'Viva Prep',
      badgeColor: 'bg-[#202429] text-[#A78BFA] text-[10px] border border-[#454B53]',
    },
    {
      id: 'settings' as NavigationTab,
      label: 'Settings & Drivers',
      icon: Settings,
      badge: null,
    },
    {
      id: 'about' as NavigationTab,
      label: 'About Project',
      icon: Info,
      badge: null,
    },
  ];

  return (
    <aside className="w-64 bg-[#191C20] border-r border-[#454B53] flex flex-col justify-between select-none shrink-0 h-[calc(100vh-4rem)] sticky top-16">
      <div className="p-3 space-y-1">
        <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-[#7F8996]">
          Navigation
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors group cursor-pointer ${
                isActive
                  ? 'bg-[#292E34] border border-[#454B53] text-[#F3F4F6] font-semibold'
                  : 'text-[#A1A8B3] hover:text-[#F3F4F6] hover:bg-[#24282D]'
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isActive ? 'text-[#60A5FA]' : 'text-[#7F8996] group-hover:text-[#A1A8B3]'
                  }`}
                />
                <span className="truncate">{item.label}</span>
              </div>

              {item.badge && (
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-semibold tracking-wide ${
                    item.badgeColor || 'bg-[#202429] text-[#A1A8B3] border border-[#454B53]'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Educational Notice Footer */}
      <div className="p-3 m-3 rounded-xl bg-[#202429] border border-[#363B42] text-[#A1A8B3] text-[11px] space-y-1.5">
        <div className="flex items-center space-x-1.5 text-[#F3F4F6] font-medium">
          <ShieldAlert className="w-3.5 h-3.5 text-[#94A3B8]" />
          <span>Educational Use Notice</span>
        </div>
        <p className="text-[10px] leading-relaxed text-[#7F8996]">
          Capture network traffic only on authorized local interfaces. Designed for Computer Networks laboratory & viva demonstrations.
        </p>
      </div>
    </aside>
  );
};
