/**
 * NetScope — About Project Page (Graphite Minimal Theme)
 * Academic objectives, implemented capabilities, limitations, and architecture summary.
 */

import React from 'react';
import { 
  Info, 
  CheckCircle2, 
  Layers, 
  AlertCircle, 
} from 'lucide-react';

export const AboutPage: React.FC = () => {
  return (
    <div className="space-y-6 pb-12 max-w-4xl mx-auto text-[#D1D5DB] text-xs">
      {/* Hero Header */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs flex items-center justify-between">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-[#94A3B8]">
            <Info className="w-6 h-6" />
            <h2 className="text-base font-bold text-[#F3F4F6]">About NetScope — Network Packet Analyser</h2>
          </div>
          <p className="text-xs text-[#A1A8B3]">
            Comprehensive Computer Networks (CN) Academic Project Demonstration System
          </p>
        </div>
        <div className="text-right font-mono text-[11px] text-[#A1A8B3]">
          <div>Release: <span className="text-[#60A5FA] font-bold">v2.4 Final</span></div>
          <div>Target: <span className="text-[#F3F4F6] font-semibold">CN Viva & Evaluation</span></div>
        </div>
      </div>

      {/* System Architecture */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
          <Layers className="w-4 h-4 text-[#94A3B8]" />
          <span>System Architecture & Technology Stack</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] space-y-2">
            <h4 className="font-bold text-[#60A5FA] border-b border-[#363B42] pb-1.5">Frontend Layer</h4>
            <ul className="space-y-1.5 text-[#D1D5DB] font-sans">
              <li>• <strong className="text-[#F3F4F6]">Framework:</strong> React 19 with Vite & TypeScript</li>
              <li>• <strong className="text-[#F3F4F6]">Styling:</strong> Tailwind CSS Graphite Minimal theme</li>
              <li>• <strong className="text-[#F3F4F6]">Charts:</strong> Recharts for reactive real-time telemetry</li>
              <li>• <strong className="text-[#F3F4F6]">Networking:</strong> Full-duplex WebSockets & REST client</li>
              <li>• <strong className="text-[#F3F4F6]">PCAP Dissector:</strong> In-browser libpcap v2.4 binary reader & generator</li>
            </ul>
          </div>

          <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] space-y-2">
            <h4 className="font-bold text-[#60A5FA] border-b border-[#363B42] pb-1.5">Backend & Packet Engine</h4>
            <ul className="space-y-1.5 text-[#D1D5DB] font-sans">
              <li>• <strong className="text-[#F3F4F6]">Core Servers:</strong> Express (Full-Stack dev) & Python 3 Flask / Scapy (Standalone)</li>
              <li>• <strong className="text-[#F3F4F6]">Capture Engine:</strong> Scapy AsyncSniffer on Windows (Npcap) & Linux</li>
              <li>• <strong className="text-[#F3F4F6]">Streaming:</strong> WebSockets / Flask-SocketIO</li>
              <li>• <strong className="text-[#F3F4F6]">Storage:</strong> SQLite database for capture sessions and packet metadata</li>
              <li>• <strong className="text-[#F3F4F6]">Filtering:</strong> Safe Abstract Syntax Tree parser (no eval)</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Implemented Features */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 text-[#34D399]" />
          <span>Implemented Feature Checklist</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          {[
            'Real-Time Packet Capture on authorized local network interfaces',
            'Layer 2 Ethernet II Frame and MAC Address Dissection',
            'Layer 3 IPv4 and IPv6 Header Breakdown (TTL, IHL, Checksum)',
            'Layer 4 TCP Segment Dissection (Flags: SYN, ACK, FIN, RST, PSH, URG)',
            'Layer 4 UDP Datagram Processing & Port Mapping',
            'ICMP Echo Ping and Traceroute Hop Identification',
            'DNS Query and Response Parser (Transaction ID, Type A/AAAA)',
            'HTTP/1.1 Request/Response and Header Extractor',
            'TLS 1.2/1.3 Handshake & Server Name Indication (SNI) Inspector',
            'Wireshark-Grade 16-Byte Hex Dump & Printable ASCII Dissector',
            'Safe Filter Engine with AST Validation (tcp, udp, ip.src == ...)',
            'Live Telemetry Charts (Packets/Sec, Bytes/Sec, Protocol Shares)',
            'SQLite Database Session Archiving & Reloading',
            'Binary PCAP Export loadable directly in Wireshark',
            'Formatted Academic Laboratory Project Report Generator',
          ].map((feat, idx) => (
            <div key={idx} className="flex items-start space-x-2 bg-[#202429] p-2.5 rounded-lg border border-[#454B53]">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#34D399] shrink-0 mt-0.5" />
              <span className="text-[#D1D5DB] text-[11px] font-sans">{feat}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Known Limitations */}
      <div className="bg-[#202429] border border-[#FBBF24]/30 rounded-2xl p-6 shadow-xs space-y-3">
        <h3 className="text-sm font-bold text-[#FBBF24] flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 text-[#FBBF24]" />
          <span>Known Architectural Scope & Limitations</span>
        </h3>

        <ul className="list-disc list-inside space-y-1.5 text-[#A1A8B3] leading-relaxed font-sans">
          <li>
            <strong className="text-[#F3F4F6]">No TLS / HTTPS Decryption:</strong> By modern cybersecurity standards, TLS payloads are mathematically protected. NetScope strictly examines handshake metadata (SNI, ciphers) without compromising encryption.
          </li>
          <li>
            <strong className="text-[#F3F4F6]">Driver Prerequisite:</strong> Live sniffing on Windows requires Npcap with WinPcap API compatibility mode. On Linux, raw socket capabilities (<code className="text-[#60A5FA] font-mono bg-[#191C20] px-1 py-0.5 rounded border border-[#363B42]">CAP_NET_RAW</code>) or root privileges are mandatory.
          </li>
          <li>
            <strong className="text-[#F3F4F6]">Switched Network Boundary:</strong> In modern Ethernet switched networks, an interface in promiscuous mode only captures broadcast/multicast traffic and traffic destined to or originating from the local host unless port mirroring (SPAN) is configured.
          </li>
        </ul>
      </div>
    </div>
  );
};
