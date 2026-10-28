/**
 * NetScope — Overview Dashboard Page (Graphite Minimal Theme)
 * High-impact network monitoring dashboard with KPIs, Recharts visualizations, top talkers, and packet stream.
 */

import React from 'react';
import { 
  ArrowUpRight, 
  ArrowDownLeft, 
  Radio, 
  Zap, 
  HardDrive
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar 
} from 'recharts';
import { Packet, CaptureStatistics } from '../types/packet';
import { PacketTable } from '../components/PacketTable';

interface OverviewPageProps {
  packets: Packet[];
  stats: CaptureStatistics;
  isCapturing: boolean;
  onStartCapture: () => void;
  onStopCapture: () => void;
  selectedPacket: Packet | null;
  onSelectPacket: (pkt: Packet) => void;
  onNavigateToTab: (tab: any) => void;
  onLoadSampleTrace: () => void;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#60A5FA',
  UDP: '#A78BFA',
  ICMP: '#FBBF24',
  ARP: '#94A3B8',
  DNS: '#34D399',
  HTTP: '#F87171',
  TLS: '#38BDF8',
  HTTPS: '#38BDF8',
  OTHER: '#A1A8B3',
};

export const OverviewPage: React.FC<OverviewPageProps> = ({
  packets,
  stats,
  isCapturing,
  onStartCapture,
  onStopCapture,
  selectedPacket,
  onSelectPacket,
  onNavigateToTab,
  onLoadSampleTrace,
}) => {
  // Protocol chart data
  const protocolData = Object.entries(stats.protocolCounts)
    .filter(([_, count]) => count > 0)
    .map(([proto, count]) => ({
      name: proto,
      value: count,
      color: PROTOCOL_COLORS[proto] || '#A1A8B3',
    }));

  // Packet size distribution data for BarChart
  const sizeDistData = Object.entries(stats.packetSizeDistribution).map(([range, count]) => ({
    range,
    packets: count,
  }));

  // Timeline data: group packets into 12 buckets
  const timelineBuckets = React.useMemo(() => {
    if (packets.length === 0) return [];
    const bucketCount = 12;
    const firstTime = packets[0].timestamp;
    const lastTime = packets[packets.length - 1].timestamp;
    const span = Math.max(1000, lastTime - firstTime);
    const step = span / bucketCount;

    const buckets = Array.from({ length: bucketCount }, (_, i) => ({
      time: `${Math.round((i * step) / 1000)}s`,
      packets: 0,
      bytes: 0,
    }));

    for (const pkt of packets) {
      const idx = Math.min(bucketCount - 1, Math.floor((pkt.timestamp - firstTime) / step));
      if (buckets[idx]) {
        buckets[idx].packets++;
        buckets[idx].bytes += pkt.length;
      }
    }

    return buckets;
  }, [packets]);

  // Unique communicating IPs
  const uniqueIps = new Set([
    ...Object.keys(stats.ipCounts.sources),
    ...Object.keys(stats.ipCounts.destinations),
  ]);

  const topSources = Object.entries(stats.ipCounts.sources)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topDestinations = Object.entries(stats.ipCounts.destinations)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Welcome Banner when empty */}
      {packets.length === 0 && (
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-4 shadow-xs">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-[#F3F4F6] flex items-center space-x-2">
              <Zap className="w-5 h-5 text-[#60A5FA]" />
              <span>Network Packet Capture & Protocol Inspection</span>
            </h2>
            <p className="text-xs text-[#A1A8B3] max-w-xl">
              Start live network sniffing on an authorized interface or load an academic sample trace to inspect Ethernet frames, IPv4/IPv6 headers, TCP 3-way handshakes, UDP datagrams, ICMP ping, and DNS queries.
            </p>
          </div>
          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={onLoadSampleTrace}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#202429] hover:bg-[#383E45] text-[#D1D5DB] border border-[#454B53] transition-colors cursor-pointer flex items-center space-x-1.5"
            >
              <HardDrive className="w-4 h-4 text-[#94A3B8]" />
              <span>Load Academic Trace</span>
            </button>
            <button
              onClick={onStartCapture}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#34D399] hover:bg-[#10B981] active:bg-[#059669] text-[#191C20] transition-colors cursor-pointer flex items-center space-x-1.5"
            >
              <Radio className="w-4 h-4" />
              <span>Start Live Capture</span>
            </button>
          </div>
        </div>
      )}

      {/* 8 KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        {/* 1. Total Packets */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">PACKETS</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#F3F4F6]">{stats.totalPackets.toLocaleString()}</span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Frames captured</span>
        </div>

        {/* 2. Total Bytes */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">DATA VOLUME</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#F3F4F6]">{formatBytes(stats.totalBytes)}</span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Total transferred</span>
        </div>

        {/* 3. Average Packet Size */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">AVG PKT SIZE</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#38BDF8]">{stats.averagePacketSize} <span className="text-xs font-normal text-[#A1A8B3]">B</span></span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Bytes per frame</span>
        </div>

        {/* 4. Packets / Sec */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">THROUGHPUT</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#34D399]">{stats.packetsPerSecond} <span className="text-xs font-normal text-[#A1A8B3]">pps</span></span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Packets / second</span>
        </div>

        {/* 5. TCP Packets */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">TCP COUNT</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#60A5FA]">{stats.protocolCounts.TCP}</span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Reliable stream</span>
        </div>

        {/* 6. UDP Packets */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">UDP COUNT</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#A78BFA]">{stats.protocolCounts.UDP}</span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Datagram traffic</span>
        </div>

        {/* 7. ICMP Packets */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">ICMP COUNT</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#FBBF24]">{stats.protocolCounts.ICMP}</span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Ping / Diagnostics</span>
        </div>

        {/* 8. Unique IPs */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-col justify-between shadow-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#7F8996]">UNIQUE IPS</span>
          <div className="mt-2">
            <span className="text-lg font-bold font-mono text-[#94A3B8]">{uniqueIps.size}</span>
          </div>
          <span className="text-[9px] text-[#7F8996] mt-1">Active nodes</span>
        </div>
      </div>

      {/* Visualizations Row: Traffic Timeline & Protocol Donut */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Traffic Rate Timeline */}
        <div className="lg:col-span-2 bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6]">Real-Time Traffic Volume Timeline</h3>
              <p className="text-[11px] text-[#A1A8B3]">Captured packet intensity across session duration</p>
            </div>
            <div className="flex items-center space-x-2 text-xs">
              <span className="flex items-center space-x-1.5 text-[#60A5FA] font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-[#60A5FA] inline-block"></span>
                <span>Packets</span>
              </span>
            </div>
          </div>

          <div className="h-56 w-full">
            {timelineBuckets.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineBuckets} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="graphiteBlueGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#60A5FA" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#60A5FA" stopOpacity={0.02}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#7F8996" fontSize={10} tickLine={false} />
                  <YAxis stroke="#7F8996" fontSize={10} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#202429', borderColor: '#454B53', borderRadius: '0.5rem', fontSize: '11px', color: '#F3F4F6', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)' }}
                    labelStyle={{ color: '#A1A8B3' }}
                  />
                  <Area type="monotone" dataKey="packets" stroke="#60A5FA" strokeWidth={2} fillOpacity={1} fill="url(#graphiteBlueGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-[#7F8996] text-xs italic">
                Awaiting packet capture data...
              </div>
            )}
          </div>
        </div>

        {/* Protocol Distribution Donut */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6]">Protocol Breakdown</h3>
              <p className="text-[11px] text-[#A1A8B3]">Layer distribution by share</p>
            </div>
          </div>

          <div className="h-44 w-full flex items-center justify-center">
            {protocolData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#202429', borderColor: '#454B53', borderRadius: '0.5rem', fontSize: '11px', color: '#F3F4F6', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-[#7F8996] text-xs italic">No protocol data</div>
            )}
          </div>

          {/* Legend list */}
          <div className="grid grid-cols-2 gap-2 mt-2 pt-3 border-t border-[#363B42] text-[11px]">
            {protocolData.slice(0, 4).map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center space-x-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-[#D1D5DB] font-medium">{item.name}</span>
                </div>
                <span className="font-mono text-[#F3F4F6] font-bold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Talkers & Packet Size Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Communicating Source IPs */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
              <ArrowUpRight className="w-4 h-4 text-[#60A5FA]" />
              <span>Top Source IP Addresses</span>
            </h3>
            <span className="text-[10px] text-[#7F8996] font-mono">By count</span>
          </div>

          <div className="space-y-2.5">
            {topSources.length > 0 ? (
              topSources.map(([ip, cnt]) => {
                const pct = stats.totalPackets > 0 ? (cnt / stats.totalPackets) * 100 : 0;
                return (
                  <div key={ip} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-[#D1D5DB] font-medium">{ip}</span>
                      <span className="text-[#60A5FA] font-bold">{cnt} pkts ({pct.toFixed(0)}%)</span>
                    </div>
                    <div className="w-full bg-[#202429] h-1.5 rounded-full overflow-hidden">
                      <div className="bg-[#60A5FA] h-full rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-[#7F8996] text-xs py-4 text-center italic">No source IPs yet</div>
            )}
          </div>
        </div>

        {/* Top Communicating Destination IPs */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
              <ArrowDownLeft className="w-4 h-4 text-[#34D399]" />
              <span>Top Destination IP Addresses</span>
            </h3>
            <span className="text-[10px] text-[#7F8996] font-mono">By count</span>
          </div>

          <div className="space-y-2.5">
            {topDestinations.length > 0 ? (
              topDestinations.map(([ip, cnt]) => {
                const pct = stats.totalPackets > 0 ? (cnt / stats.totalPackets) * 100 : 0;
                return (
                  <div key={ip} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-[#D1D5DB] font-medium">{ip}</span>
                      <span className="text-[#34D399] font-bold">{cnt} pkts ({pct.toFixed(0)}%)</span>
                    </div>
                    <div className="w-full bg-[#202429] h-1.5 rounded-full overflow-hidden">
                      <div className="bg-[#34D399] h-full rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-[#7F8996] text-xs py-4 text-center italic">No destination IPs yet</div>
            )}
          </div>
        </div>

        {/* Packet Size Histogram */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-bold text-[#F3F4F6]">Packet Size Distribution</h3>
            <span className="text-[10px] text-[#7F8996]">Bytes per frame</span>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sizeDistData} margin={{ top: 10, right: 0, left: -25, bottom: 0 }}>
                <XAxis dataKey="range" stroke="#7F8996" fontSize={9} tickLine={false} />
                <YAxis stroke="#7F8996" fontSize={9} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#202429', borderColor: '#454B53', borderRadius: '0.5rem', fontSize: '11px', color: '#F3F4F6', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)' }}
                />
                <Bar dataKey="packets" fill="#38BDF8" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Packets Feed */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#F3F4F6]">Recent Captured Packets</h3>
            <p className="text-[11px] text-[#A1A8B3]">Latest frames passing through selected interface</p>
          </div>
          <button
            onClick={() => onNavigateToTab('live-capture')}
            className="text-xs text-[#60A5FA] hover:text-[#93C5FD] font-semibold cursor-pointer transition-colors"
          >
            Open Live Workstation →
          </button>
        </div>

        <div className="h-80">
          <PacketTable
            packets={packets.slice(-15).reverse()}
            selectedPacket={selectedPacket}
            onSelectPacket={onSelectPacket}
          />
        </div>
      </div>
    </div>
  );
};
