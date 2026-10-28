/**
 * NetScope — Top Navigation Bar (Graphite Minimal Theme)
 */

import React from 'react';
import { 
  Activity, 
  Wifi, 
  Play, 
  Square, 
  Trash2, 
  HardDrive,
  Download
} from 'lucide-react';
import { NetworkInterface } from '../types/packet';

interface NavbarProps {
  interfaces: NetworkInterface[];
  selectedInterface: string;
  onSelectInterface: (name: string) => void;
  isCapturing: boolean;
  onStartCapture: () => void;
  onStopCapture: () => void;
  onClearPackets: () => void;
  packetCount: number;
  totalBytes: number;
  packetsPerSec: number;
  isConnected: boolean;
  onOpenExport: () => void;
  onLoadSampleTrace: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  interfaces,
  selectedInterface,
  onSelectInterface,
  isCapturing,
  onStartCapture,
  onStopCapture,
  onClearPackets,
  packetCount,
  totalBytes,
  packetsPerSec,
  isConnected,
  onOpenExport,
  onLoadSampleTrace,
}) => {
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <header className="h-16 bg-[#24282D] border-b border-[#454B53] text-[#D1D5DB] flex items-center justify-between px-5 select-none z-30 sticky top-0">
      {/* Brand & Logo */}
      <div className="flex items-center space-x-3">
        <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-[#30353B] border border-[#454B53] text-[#94A3B8]">
          <Activity className="w-4 h-4 text-[#94A3B8]" />
          <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
            {isCapturing && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#34D399] opacity-75"></span>
            )}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${isCapturing ? 'bg-[#34D399]' : 'bg-[#626B76]'}`}></span>
          </span>
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-base tracking-tight text-[#F3F4F6]">
              NetScope
            </span>
            <span className="text-[10px] font-mono tracking-wider uppercase px-2 py-0.5 rounded bg-[#202429] border border-[#454B53] text-[#A1A8B3]">
              V2.4 CN EDITION
            </span>
          </div>
          <p className="text-[11px] text-[#A1A8B3] font-normal">Network Packet Analyser & Observability</p>
        </div>
      </div>

      {/* Interface Selector & Capture Controls */}
      <div className="flex items-center space-x-2.5">
        {/* Network Interface Dropdown */}
        <div className="flex items-center space-x-2 bg-[#202429] border border-[#454B53] rounded-lg px-2.5 py-1.5 text-xs text-[#D1D5DB]">
          <Wifi className="w-3.5 h-3.5 text-[#94A3B8]" />
          <select
            value={selectedInterface}
            onChange={(e) => onSelectInterface(e.target.value)}
            disabled={isCapturing}
            className="bg-transparent text-[#D1D5DB] outline-none text-xs cursor-pointer font-medium disabled:opacity-50"
            title="Select Local Network Interface"
          >
            {interfaces.map((iface) => (
              <option key={iface.id} value={iface.name} className="bg-[#24282D] text-[#D1D5DB]">
                {iface.name} ({iface.type.toUpperCase()}) — {iface.ip4 || 'No IPv4'}
              </option>
            ))}
            {interfaces.length === 0 && (
              <option value="default" className="bg-[#24282D] text-[#D1D5DB]">
                Default Interface
              </option>
            )}
          </select>
        </div>

        {/* Capture Start / Stop Buttons */}
        {!isCapturing ? (
          <button
            onClick={onStartCapture}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#34D399] hover:bg-[#10B981] active:bg-[#059669] text-[#191C20] transition-colors cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Start Capture</span>
          </button>
        ) : (
          <button
            onClick={onStopCapture}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#F87171] hover:bg-[#EF4444] active:bg-[#DC2626] text-[#191C20] transition-colors cursor-pointer"
          >
            <Square className="w-3.5 h-3.5 fill-current" />
            <span>Stop Capture</span>
          </button>
        )}

        {/* Clear Button */}
        <button
          onClick={onClearPackets}
          disabled={isCapturing && packetCount === 0}
          className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-[#D1D5DB] hover:text-[#F3F4F6] bg-[#292E34] hover:bg-[#383E45] border border-[#454B53] transition-colors cursor-pointer disabled:opacity-40"
          title="Clear captured packets in memory"
        >
          <Trash2 className="w-3.5 h-3.5 text-[#A1A8B3]" />
          <span>Clear</span>
        </button>

        {/* Sample Trace Loader for instant academic demo */}
        <button
          onClick={onLoadSampleTrace}
          className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-[#D1D5DB] hover:text-[#F3F4F6] bg-[#292E34] hover:bg-[#383E45] border border-[#454B53] transition-colors cursor-pointer"
          title="Load academic reference trace (DNS, TCP 3-Way Handshake, ICMP Ping, HTTP, TLS)"
        >
          <HardDrive className="w-3.5 h-3.5 text-[#94A3B8]" />
          <span>Sample Trace</span>
        </button>

        {/* Export Button */}
        <button
          onClick={onOpenExport}
          className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-[#D1D5DB] hover:text-[#F3F4F6] bg-[#292E34] hover:bg-[#383E45] border border-[#454B53] transition-colors cursor-pointer"
          title="Export CSV, JSON, PCAP or Academic Report"
        >
          <Download className="w-3.5 h-3.5 text-[#94A3B8]" />
          <span>Export</span>
        </button>
      </div>

      {/* Right Stats & Backend Connection Indicator */}
      <div className="flex items-center space-x-3">
        {/* Live Counters */}
        <div className="hidden lg:flex items-center space-x-3 text-xs bg-[#202429] border border-[#454B53] rounded-lg px-3 py-1.5">
          <div className="flex flex-col">
            <span className="text-[10px] text-[#7F8996] font-medium">PACKETS</span>
            <span className="font-mono font-semibold text-[#F3F4F6]">{packetCount.toLocaleString()}</span>
          </div>
          <div className="h-6 w-px bg-[#363B42]"></div>
          <div className="flex flex-col">
            <span className="text-[10px] text-[#7F8996] font-medium">DATA</span>
            <span className="font-mono font-semibold text-[#F3F4F6]">{formatBytes(totalBytes)}</span>
          </div>
          <div className="h-6 w-px bg-[#363B42]"></div>
          <div className="flex flex-col">
            <span className="text-[10px] text-[#7F8996] font-medium">RATE</span>
            <span className="font-mono font-semibold text-[#34D399]">{packetsPerSec} pps</span>
          </div>
        </div>

        {/* Backend Connection Status */}
        <div 
          className="flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-md border border-[#454B53] bg-[#202429] text-[#A1A8B3] font-medium"
          title={isConnected ? 'Connected to NetScope Packet Engine' : 'Reconnecting to Packet Engine...'}
        >
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-[#34D399]' : 'bg-[#FBBF24] animate-ping'}`} />
          <span>{isConnected ? 'Engine Online' : 'Connecting'}</span>
        </div>
      </div>
    </header>
  );
};
