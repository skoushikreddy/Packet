/**
 * NetScope — Protocol Analysis Page (Graphite Minimal Theme)
 * Comprehensive OSI/TCP-IP layer decomposition, port distributions, and network conversation matrices.
 */

import React from 'react';
import { 
  PieChart as PieIcon, 
  Layers, 
  HelpCircle, 
  ArrowRightLeft, 
  Hash, 
} from 'lucide-react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';
import { Packet, CaptureStatistics } from '../types/packet';

interface ProtocolAnalysisPageProps {
  packets: Packet[];
  stats: CaptureStatistics;
}

const PROTOCOL_PALETTE: Record<string, string> = {
  TCP: '#60A5FA',
  UDP: '#A78BFA',
  ICMP: '#FBBF24',
  DNS: '#34D399',
  HTTP: '#F87171',
  TLS: '#38BDF8',
  ARP: '#94A3B8',
  OTHER: '#A1A8B3',
};

const DEFAULT_COLORS = ['#60A5FA', '#A78BFA', '#FBBF24', '#34D399', '#F87171', '#38BDF8', '#94A3B8', '#A1A8B3'];

export const ProtocolAnalysisPage: React.FC<ProtocolAnalysisPageProps> = ({
  stats,
}) => {
  // Protocol breakdown
  const protocolEntries = Object.entries(stats.protocolCounts)
    .filter(([_, count]) => count > 0)
    .sort((a, b) => b[1] - a[1]);

  const pieData = protocolEntries.map(([name, value]) => ({
    name,
    value,
  }));

  // Top Ports
  const topPorts = Object.entries(stats.portCounts)
    .map(([port, count]) => {
      const pNum = Number(port);
      let service = 'Unknown';
      if (pNum === 80) service = 'HTTP';
      else if (pNum === 443) service = 'HTTPS / TLS';
      else if (pNum === 53) service = 'DNS';
      else if (pNum === 22) service = 'SSH';
      else if (pNum === 21) service = 'FTP';
      else if (pNum === 25) service = 'SMTP';
      else if (pNum === 67 || pNum === 68) service = 'DHCP';
      else if (pNum >= 49152) service = 'Dynamic / Ephemeral';

      return {
        port: pNum,
        service,
        count,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // Top Conversations (A <-> B)
  const topConversations = Object.entries(stats.ipCounts.conversations)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  return (
    <div className="space-y-6 pb-12">
      {/* Page Header */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs">
        <div className="space-y-1">
          <h2 className="text-base font-bold text-[#F3F4F6] flex items-center space-x-2">
            <PieIcon className="w-5 h-5 text-[#94A3B8]" />
            <span>Deep Protocol Layer Analysis & Decomposition</span>
          </h2>
          <p className="text-xs text-[#A1A8B3]">
            Analysis of captured frames across OSI Reference Model layers (Data Link, Network, Transport, and Application).
          </p>
        </div>
        <div className="flex items-center space-x-2 text-xs text-[#A1A8B3] bg-[#202429] px-3 py-1.5 rounded-lg border border-[#454B53]">
          <Layers className="w-4 h-4 text-[#94A3B8]" />
          <span>Analyzed Frames: <strong className="text-[#F3F4F6] font-mono">{stats.totalPackets.toLocaleString()}</strong></span>
        </div>
      </div>

      {/* Protocol Shares Grid & Donut */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Protocol Donut Chart */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <h3 className="text-sm font-bold text-[#F3F4F6] mb-2">Protocol Distribution (By Frame Count)</h3>

          <div className="h-56 w-full flex items-center justify-center">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={PROTOCOL_PALETTE[entry.name] || DEFAULT_COLORS[index % DEFAULT_COLORS.length]} 
                      />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#202429', 
                      borderColor: '#454B53', 
                      borderRadius: '0.5rem', 
                      fontSize: '11px', 
                      color: '#F3F4F6',
                      boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)' 
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-[#7F8996] text-xs italic">No protocol data available</div>
            )}
          </div>

          <div className="text-[11px] text-[#A1A8B3] text-center">
            Proportional representation of identified layer protocols
          </div>
        </div>

        {/* Detailed Protocol Table */}
        <div className="lg:col-span-2 bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#F3F4F6] mb-1">Protocol Breakdown & Percentage Shares</h3>
            <p className="text-[11px] text-[#A1A8B3] mb-4">Detailed metrics on encapsulated payload classifications</p>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#202429] text-[#A1A8B3] uppercase text-[10px] font-semibold border-b border-[#454B53]">
                  <tr>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Layer (OSI / TCP-IP)</th>
                    <th className="py-2.5 px-3 text-right">Frame Count</th>
                    <th className="py-2.5 px-3 text-right">Share (%)</th>
                    <th className="py-2.5 px-3">Traffic Category</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#363B42] font-mono">
                  {protocolEntries.map(([proto, count], idx) => {
                    const pct = stats.totalPackets > 0 ? (count / stats.totalPackets) * 100 : 0;
                    let layer = 'Layer 4 (Transport)';
                    let cat = 'Connection-Oriented';

                    if (proto === 'ARP') { layer = 'Layer 2/3 (Data Link / Net)'; cat = 'Address Resolution'; }
                    else if (proto === 'ICMP') { layer = 'Layer 3 (Network Control)'; cat = 'Diagnostics & Ping'; }
                    else if (proto === 'UDP') { layer = 'Layer 4 (Transport)'; cat = 'Datagrams / Connectionless'; }
                    else if (proto === 'DNS') { layer = 'Layer 7 (Application)'; cat = 'Domain Name Resolution'; }
                    else if (proto === 'HTTP') { layer = 'Layer 7 (Application)'; cat = 'Web REST Traffic'; }
                    else if (proto === 'TLS') { layer = 'Layer 7 (Application)'; cat = 'Encrypted HTTPS Session'; }

                    const badgeColor = PROTOCOL_PALETTE[proto] || DEFAULT_COLORS[idx % DEFAULT_COLORS.length];

                    return (
                      <tr key={proto} className="hover:bg-[#383E45]/40 transition-colors">
                        <td className="py-2 px-3 font-bold text-[#F3F4F6]">
                          <span className="inline-block w-2 h-2 rounded-full mr-2" style={{ backgroundColor: badgeColor }}></span>
                          {proto}
                        </td>
                        <td className="py-2 px-3 text-[#D1D5DB] font-sans">{layer}</td>
                        <td className="py-2 px-3 text-right font-bold text-[#F3F4F6]">{count.toLocaleString()}</td>
                        <td className="py-2 px-3 text-right text-[#34D399] font-bold">{pct.toFixed(1)}%</td>
                        <td className="py-2 px-3 text-[#A1A8B3] font-sans">{cat}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4 p-3 rounded-xl bg-[#202429] border border-[#363B42] text-[11px] text-[#A1A8B3] flex items-start space-x-2">
            <HelpCircle className="w-4 h-4 text-[#94A3B8] shrink-0 mt-0.5" />
            <span>
              <strong>Note on Encapsulation:</strong> When a packet contains multiple layers (e.g. Ethernet Frame → IPv4 Header → TCP Segment → TLS Record), 
              the protocol column denotes the highest decoded application layer protocol while underlying headers remain fully dissectible.
            </span>
          </div>
        </div>
      </div>

      {/* Top Ports & Network Conversations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Most Frequently Used Ports */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
                <Hash className="w-4 h-4 text-[#94A3B8]" />
                <span>Most Frequently Used Ports</span>
              </h3>
              <p className="text-[11px] text-[#A1A8B3]">Layer 4 port activity across TCP & UDP</p>
            </div>
            <span className="text-[10px] text-[#7F8996] font-mono">By frame count</span>
          </div>

          <div className="space-y-3">
            {topPorts.length > 0 ? (
              topPorts.map((item) => {
                const pct = stats.totalPackets > 0 ? (item.count / stats.totalPackets) * 100 : 0;
                return (
                  <div key={item.port} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-[#60A5FA]">Port {item.port}</span>
                        <span className="text-[#A1A8B3] text-[11px]">({item.service})</span>
                      </div>
                      <span className="text-[#F3F4F6] font-bold">{item.count} pkts ({pct.toFixed(0)}%)</span>
                    </div>
                    <div className="w-full bg-[#202429] h-1.5 rounded-full overflow-hidden">
                      <div className="bg-[#60A5FA] h-full rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-[#7F8996] text-xs py-4 text-center italic">No port data available</div>
            )}
          </div>
        </div>

        {/* IP Conversations (Who is talking to whom) */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
                <ArrowRightLeft className="w-4 h-4 text-[#34D399]" />
                <span>Top IP Conversations (Talkers)</span>
              </h3>
              <p className="text-[11px] text-[#A1A8B3]">Bidirectional communicating node pairs</p>
            </div>
            <span className="text-[10px] text-[#7F8996] font-mono">Conversations</span>
          </div>

          <div className="space-y-2.5">
            {topConversations.length > 0 ? (
              topConversations.map(([conv, count]) => {
                const pct = stats.totalPackets > 0 ? (count / stats.totalPackets) * 100 : 0;
                return (
                  <div key={conv} className="p-2.5 rounded-xl bg-[#202429] border border-[#363B42] space-y-1.5">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="font-medium text-[#F3F4F6]">{conv}</span>
                      <span className="text-[#34D399] font-bold">{count} pkts</span>
                    </div>
                    <div className="w-full bg-[#191C20] h-1 rounded-full overflow-hidden">
                      <div className="bg-[#34D399] h-full rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-[#7F8996] text-xs py-4 text-center italic">No conversations recorded</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
