/**
 * NetScope — Real-Time Traffic Observability & Network Monitoring (Graphite Minimal Theme)
 * Metrics: PPS, BPS, Incoming vs Outgoing bandwidth, TCP vs UDP shares, packet size histograms.
 */

import React, { useMemo } from 'react';
import { 
  TrendingUp, 
  ArrowUpRight, 
  ArrowDownLeft, 
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  BarChart, 
  Bar 
} from 'recharts';
import { Packet, CaptureStatistics } from '../types/packet';

interface TrafficMonitorPageProps {
  packets: Packet[];
  stats: CaptureStatistics;
  isCapturing: boolean;
}

export const TrafficMonitorPage: React.FC<TrafficMonitorPageProps> = ({
  packets,
  stats,
}) => {
  // Compute time buckets for PPS and BPS
  const rateSeries = useMemo(() => {
    if (packets.length === 0) return [];
    const count = 16;
    const first = packets[0].timestamp;
    const last = packets[packets.length - 1].timestamp;
    const span = Math.max(1000, last - first);
    const step = span / count;

    const data = Array.from({ length: count }, (_, i) => ({
      time: `${Math.round((i * step) / 1000)}s`,
      packets: 0,
      bytes: 0,
      tcp: 0,
      udp: 0,
      incoming: 0,
      outgoing: 0,
    }));

    for (const pkt of packets) {
      const idx = Math.min(count - 1, Math.floor((pkt.timestamp - first) / step));
      if (data[idx]) {
        data[idx].packets++;
        data[idx].bytes += pkt.length;
        if (pkt.protocol === 'TCP' || pkt.protocol === 'HTTP' || pkt.protocol === 'TLS') data[idx].tcp++;
        if (pkt.protocol === 'UDP' || pkt.protocol === 'DNS') data[idx].udp++;
        if (pkt.direction === 'OUTGOING') data[idx].outgoing += pkt.length;
        else data[idx].incoming += pkt.length;
      }
    }

    return data;
  }, [packets]);

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs">
        <div className="space-y-1">
          <h2 className="text-base font-bold text-[#F3F4F6] flex items-center space-x-2">
            <TrendingUp className="w-5 h-5 text-[#94A3B8]" />
            <span>Real-Time Traffic Observability & Bandwidth Metrics</span>
          </h2>
          <p className="text-xs text-[#A1A8B3]">
            Live telemetry of packets per second, transfer rates, directionality, and transport layer ratios.
          </p>
        </div>
        <div className="flex items-center space-x-3 text-xs">
          <div className="bg-[#202429] px-3 py-1.5 rounded-lg border border-[#454B53] flex items-center space-x-2">
            <span className="text-[#7F8996]">CURRENT PPS:</span>
            <span className="font-mono font-bold text-[#34D399]">{stats.packetsPerSecond} pps</span>
          </div>
          <div className="bg-[#202429] px-3 py-1.5 rounded-lg border border-[#454B53] flex items-center space-x-2">
            <span className="text-[#7F8996]">BANDWIDTH:</span>
            <span className="font-mono font-bold text-[#38BDF8]">{formatBytes(stats.bytesPerSecond)}/s</span>
          </div>
        </div>
      </div>

      {/* Primary Charts: PPS & BPS over time */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Packets Per Second Chart */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6]">Packet Throughput (Packets/Second)</h3>
              <p className="text-[11px] text-[#A1A8B3]">Rate of network frame transmission</p>
            </div>
            <span className="text-xs font-mono font-semibold text-[#60A5FA] bg-[#202429] px-2.5 py-1 rounded-md border border-[#454B53]">
              {stats.packetsPerSecond} pps avg
            </span>
          </div>

          <div className="h-56 w-full">
            {rateSeries.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={rateSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="ppsGraphiteGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#60A5FA" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#60A5FA" stopOpacity={0.02}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#7F8996" fontSize={10} tickLine={false} />
                  <YAxis stroke="#7F8996" fontSize={10} tickLine={false} />
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
                  <Area type="monotone" dataKey="packets" name="Packets" stroke="#60A5FA" strokeWidth={2} fillOpacity={1} fill="url(#ppsGraphiteGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-[#7F8996] text-xs italic">
                Awaiting network traffic...
              </div>
            )}
          </div>
        </div>

        {/* Bytes Per Second Chart */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6]">Data Transfer Rate (Bytes/Second)</h3>
              <p className="text-[11px] text-[#A1A8B3]">Total bandwidth consumption on link</p>
            </div>
            <span className="text-xs font-mono font-semibold text-[#34D399] bg-[#202429] px-2.5 py-1 rounded-md border border-[#454B53]">
              {formatBytes(stats.bytesPerSecond)}/s
            </span>
          </div>

          <div className="h-56 w-full">
            {rateSeries.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={rateSeries} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="bytesGraphiteGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#34D399" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#34D399" stopOpacity={0.02}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#7F8996" fontSize={10} tickLine={false} />
                  <YAxis stroke="#7F8996" fontSize={10} tickLine={false} tickFormatter={(v) => `${(v/1024).toFixed(0)}KB`} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#202429', 
                      borderColor: '#454B53', 
                      borderRadius: '0.5rem', 
                      fontSize: '11px', 
                      color: '#F3F4F6',
                      boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)' 
                    }}
                    formatter={(v: any) => [`${formatBytes(Number(v))}`, 'Bytes']}
                  />
                  <Area type="monotone" dataKey="bytes" name="Bytes" stroke="#34D399" strokeWidth={2} fillOpacity={1} fill="url(#bytesGraphiteGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-[#7F8996] text-xs italic">
                Awaiting network traffic...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Secondary Charts: TCP vs UDP & Ingress vs Egress */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* TCP vs UDP Flow Comparison */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6]">TCP vs UDP Traffic Intensity</h3>
              <p className="text-[11px] text-[#A1A8B3]">Connection-oriented vs datagram delivery comparison</p>
            </div>
            <div className="flex items-center space-x-3 text-xs">
              <span className="flex items-center space-x-1.5 text-[#60A5FA] font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-[#60A5FA] inline-block"></span>
                <span>TCP</span>
              </span>
              <span className="flex items-center space-x-1.5 text-[#A78BFA] font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-[#A78BFA] inline-block"></span>
                <span>UDP</span>
              </span>
            </div>
          </div>

          <div className="h-52 w-full">
            {rateSeries.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rateSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="time" stroke="#7F8996" fontSize={10} tickLine={false} />
                  <YAxis stroke="#7F8996" fontSize={10} tickLine={false} />
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
                  <Line type="monotone" dataKey="tcp" stroke="#60A5FA" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="udp" stroke="#A78BFA" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-[#7F8996] text-xs italic">
                No packet data available
              </div>
            )}
          </div>
        </div>

        {/* Inbound vs Outbound Bandwidth */}
        <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-bold text-[#F3F4F6]">Ingress vs Egress Bandwidth</h3>
              <p className="text-[11px] text-[#A1A8B3]">Traffic direction determined by local subnet routing</p>
            </div>
            <div className="flex items-center space-x-3 text-xs">
              <span className="flex items-center space-x-1 text-[#34D399] font-medium bg-[#202429] px-2 py-0.5 rounded border border-[#454B53]">
                <ArrowDownLeft className="w-3.5 h-3.5" />
                <span>In ({stats.directionCounts.INCOMING})</span>
              </span>
              <span className="flex items-center space-x-1 text-[#60A5FA] font-medium bg-[#202429] px-2 py-0.5 rounded border border-[#454B53]">
                <ArrowUpRight className="w-3.5 h-3.5" />
                <span>Out ({stats.directionCounts.OUTGOING})</span>
              </span>
            </div>
          </div>

          <div className="h-52 w-full">
            {rateSeries.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={rateSeries} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <XAxis dataKey="time" stroke="#7F8996" fontSize={10} tickLine={false} />
                  <YAxis stroke="#7F8996" fontSize={10} tickLine={false} tickFormatter={(v) => `${(v/1024).toFixed(0)}KB`} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#202429', 
                      borderColor: '#454B53', 
                      borderRadius: '0.5rem', 
                      fontSize: '11px', 
                      color: '#F3F4F6',
                      boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)' 
                    }}
                    formatter={(v: any) => [`${formatBytes(Number(v))}`]}
                  />
                  <Bar dataKey="incoming" name="Ingress Bytes" fill="#34D399" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="outgoing" name="Egress Bytes" fill="#60A5FA" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-[#7F8996] text-xs italic">
                No direction data available
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
