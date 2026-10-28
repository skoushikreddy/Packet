/**
 * NetScope — Academic Computer Networks Knowledge Portal & Viva Prep (Graphite Minimal Theme)
 * Explains OSI vs TCP/IP, Ethernet, IPv4 vs IPv6, TCP 3-Way Handshake, ICMP, DNS, and Viva Voce Q&A.
 */

import React, { useState } from 'react';
import { 
  GraduationCap, 
  Layers, 
  ChevronDown, 
  ChevronRight, 
  BookOpen, 
  Zap, 
  HelpCircle 
} from 'lucide-react';

export const AcademicGuidePage: React.FC = () => {
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const VIVA_QUESTIONS = [
    {
      q: 'What is a packet analyser / packet sniffer, and how does NetScope work?',
      a: 'A packet analyser is a computer program that intercepts and logs traffic passing over a digital network. NetScope captures frames from an authorized network interface using raw sockets / Scapy (with Npcap driver on Windows), decodes the encapsulated headers across Layers 2 through 7, and presents real-time telemetry and dissection.',
    },
    {
      q: 'Explain the difference between the OSI 7-Layer model and the TCP/IP 4-Layer model.',
      a: 'The OSI model is a theoretical 7-layer architecture (Physical, Data Link, Network, Transport, Session, Presentation, Application). The TCP/IP model is the practical 4-layer architecture of the modern Internet (Link/Network Access, Internet, Transport, Application). In TCP/IP, OSI layers 5, 6, and 7 are collapsed into the Application layer.',
    },
    {
      q: 'How does the TCP 3-Way Handshake establish a reliable connection?',
      a: '1. SYN: Client sends a TCP segment with SYN flag set and an initial sequence number (ISN_c).\n2. SYN-ACK: Server responds with SYN and ACK flags set, acknowledging ISN_c + 1 and choosing its own ISN_s.\n3. ACK: Client sends an ACK segment confirming ISN_s + 1. The full-duplex virtual circuit is now established.',
    },
    {
      q: 'What is the role of ARP (Address Resolution Protocol)?',
      a: 'ARP resolves a known Layer 3 IP address to a physical Layer 2 MAC address within a local broadcast domain. The sender broadcasts an "ARP Request (Who has X.X.X.X? Tell Y.Y.Y.Y)" to MAC ff:ff:ff:ff:ff:ff, and the target node replies with a unicast "ARP Reply" containing its MAC address.',
    },
    {
      q: 'How does ICMP Ping determine round-trip time and path reachability?',
      a: 'ICMP Echo Request (Type 8, Code 0) is transmitted to the destination with an identifier and sequence number. The receiver replies with ICMP Echo Reply (Type 0, Code 0). The difference between packet transmission and reply arrival represents round-trip latency (RTT). If Time-to-Live (TTL) reaches 0 at a router, an ICMP Time Exceeded (Type 11) is returned.',
    },
    {
      q: 'Why can NetScope inspect TLS metadata without decrypting HTTPS payloads?',
      a: 'During TLS session initiation (TLS 1.2 or 1.3), the initial "Client Hello" packet contains unencrypted handshake metadata including the Server Name Indication (SNI) extension and offered cipher suites. Once the cryptographic key exchange completes, subsequent Application Data records are end-to-end encrypted and cannot be read without private session keys.',
    },
    {
      q: 'What is the purpose of the IPv4 Header Length (IHL) and Time to Live (TTL)?',
      a: 'IHL indicates the length of the IP header in 32-bit (4-byte) words. Standard header without options has IHL=5 (20 bytes). TTL prevents packets from looping infinitely in routing loops: every router decrements TTL by 1; if TTL drops to 0, the packet is discarded and an ICMP Time Exceeded message is sent back.',
    },
  ];

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto text-[#D1D5DB] text-xs">
      {/* Title */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs flex items-center justify-between">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-[#94A3B8]">
            <GraduationCap className="w-6 h-6" />
            <h2 className="text-base font-bold text-[#F3F4F6]">Computer Networks Concepts & Viva Reference</h2>
          </div>
          <p className="text-xs text-[#A1A8B3]">
            Comprehensive curriculum alignment covering protocol headers, encapsulation, handshakes, and exam questions.
          </p>
        </div>
        <span className="px-3 py-1 rounded-lg bg-[#202429] border border-[#454B53] text-[#A1A8B3] font-mono text-[11px] font-medium">
          CN Syllabus Alignment
        </span>
      </div>

      {/* 1. OSI vs TCP/IP Interactive Comparison */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex items-center space-x-2 text-sm font-bold text-[#F3F4F6]">
          <Layers className="w-5 h-5 text-[#94A3B8]" />
          <span>1. OSI 7-Layer Model vs TCP/IP 4-Layer Architecture</span>
        </div>

        <p className="text-[#A1A8B3] leading-relaxed">
          Network data transmission relies on hierarchical encapsulation: application data travels downward through the protocol stack, gaining headers at each layer, transmitted as raw bits over the physical medium, and decapsulated at the destination.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          {/* OSI Model */}
          <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] space-y-2">
            <h4 className="font-bold text-[#F3F4F6] border-b border-[#363B42] pb-1.5 flex justify-between">
              <span>OSI 7-Layer Reference Model</span>
              <span className="text-[10px] text-[#7F8996] font-sans">ISO Standard</span>
            </h4>
            <div className="space-y-1.5 font-mono text-[11px]">
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#F87171]">7. Application</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">HTTP, DNS, SSH, FTP</span>
              </div>
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#A78BFA]">6. Presentation</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">TLS/SSL, ASCII, JSON</span>
              </div>
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#94A3B8]">5. Session</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">Sockets, RPC, NetBIOS</span>
              </div>
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#60A5FA]">4. Transport</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">TCP (Reliable), UDP (Datagram)</span>
              </div>
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#38BDF8]">3. Network</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">IPv4, IPv6, ICMP, Routing</span>
              </div>
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#FBBF24]">2. Data Link</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">Ethernet, MAC, ARP, Switches</span>
              </div>
              <div className="p-2 rounded bg-[#292E34] border border-[#454B53] text-[#F3F4F6] flex justify-between items-center">
                <span className="font-semibold text-[#34D399]">1. Physical</span>
                <span className="text-[10px] text-[#A1A8B3] font-sans">Cables, Fiber, Radio (Bits)</span>
              </div>
            </div>
          </div>

          {/* TCP/IP Model */}
          <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] space-y-2">
            <h4 className="font-bold text-[#F3F4F6] border-b border-[#363B42] pb-1.5 flex justify-between">
              <span>TCP/IP 4-Layer Architecture</span>
              <span className="text-[10px] text-[#60A5FA] font-mono">Internet Protocol Suite</span>
            </h4>
            <div className="space-y-2 font-mono text-[11px]">
              <div className="p-3 rounded bg-[#292E34] border border-[#454B53] space-y-0.5">
                <div className="flex justify-between font-bold text-[#F3F4F6]">
                  <span className="text-[#F87171]">Application Layer</span>
                  <span className="text-[10px] text-[#7F8996] font-normal">OSI 5, 6 & 7</span>
                </div>
                <p className="text-[10px] text-[#A1A8B3] font-sans">
                  User applications, protocol requests, and representation (HTTP, HTTPS, DNS, DHCP, SSH).
                </p>
              </div>

              <div className="p-3 rounded bg-[#292E34] border border-[#454B53] space-y-0.5">
                <div className="flex justify-between font-bold text-[#F3F4F6]">
                  <span className="text-[#60A5FA]">Transport Layer</span>
                  <span className="text-[10px] text-[#7F8996] font-normal">OSI 4</span>
                </div>
                <p className="text-[10px] text-[#A1A8B3] font-sans">
                  Host-to-host process communication using port numbers (TCP virtual circuits & UDP datagrams).
                </p>
              </div>

              <div className="p-3 rounded bg-[#292E34] border border-[#454B53] space-y-0.5">
                <div className="flex justify-between font-bold text-[#F3F4F6]">
                  <span className="text-[#38BDF8]">Internet Layer</span>
                  <span className="text-[10px] text-[#7F8996] font-normal">OSI 3</span>
                </div>
                <p className="text-[10px] text-[#A1A8B3] font-sans">
                  Logical addressing and global packet routing (IPv4, IPv6, ICMP diagnostics).
                </p>
              </div>

              <div className="p-3 rounded bg-[#292E34] border border-[#454B53] space-y-0.5">
                <div className="flex justify-between font-bold text-[#F3F4F6]">
                  <span className="text-[#FBBF24]">Network Access / Link Layer</span>
                  <span className="text-[10px] text-[#7F8996] font-normal">OSI 1 & 2</span>
                </div>
                <p className="text-[10px] text-[#A1A8B3] font-sans">
                  Physical frame transmission on local LAN hardware (Ethernet II, MAC addresses, ARP).
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. TCP 3-Way Handshake Visualizer */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex items-center space-x-2 text-sm font-bold text-[#F3F4F6]">
          <Zap className="w-5 h-5 text-[#60A5FA]" />
          <span>2. TCP Connection Establishment: 3-Way Handshake</span>
        </div>

        <p className="text-[#A1A8B3] leading-relaxed">
          Before data transmission can occur in TCP, a reliable virtual circuit is established through a three-step exchange of SYN and ACK control flags:
        </p>

        <div className="bg-[#202429] p-5 rounded-xl border border-[#454B53] space-y-3 font-mono text-[11px]">
          {/* Step 1 */}
          <div className="flex items-center space-x-4">
            <span className="w-24 font-bold text-[#7F8996] font-sans text-xs">Step 1 (SYN)</span>
            <div className="flex-1 bg-[#292E34] p-3 rounded-lg border border-[#454B53] flex justify-between items-center text-[#60A5FA]">
              <span>Client → Server: <strong className="text-[#F3F4F6]">[SYN]</strong> Seq = X</span>
              <span className="text-[10px] text-[#7F8996] font-sans">Client synchronizes initial sequence number</span>
            </div>
          </div>

          {/* Step 2 */}
          <div className="flex items-center space-x-4">
            <span className="w-24 font-bold text-[#7F8996] font-sans text-xs">Step 2 (SYN-ACK)</span>
            <div className="flex-1 bg-[#292E34] p-3 rounded-lg border border-[#454B53] flex justify-between items-center text-[#60A5FA]">
              <span>Server → Client: <strong className="text-[#F3F4F6]">[SYN, ACK]</strong> Seq = Y, Ack = X + 1</span>
              <span className="text-[10px] text-[#7F8996] font-sans">Server acknowledges client & sends its own ISN</span>
            </div>
          </div>

          {/* Step 3 */}
          <div className="flex items-center space-x-4">
            <span className="w-24 font-bold text-[#7F8996] font-sans text-xs">Step 3 (ACK)</span>
            <div className="flex-1 bg-[#292E34] p-3 rounded-lg border border-[#454B53] flex justify-between items-center text-[#34D399]">
              <span>Client → Server: <strong className="text-[#F3F4F6]">[ACK]</strong> Seq = X + 1, Ack = Y + 1</span>
              <span className="text-[10px] text-[#7F8996] font-sans">Connection established (ESTABLISHED state)</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Header Structures Reference (Ethernet, IPv4, TCP, UDP) */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex items-center space-x-2 text-sm font-bold text-[#F3F4F6]">
          <BookOpen className="w-5 h-5 text-[#94A3B8]" />
          <span>3. Protocol Header Specifications</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* IPv4 Header */}
          <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] space-y-2">
            <h4 className="font-bold text-[#60A5FA] flex justify-between border-b border-[#363B42] pb-1.5">
              <span>IPv4 Header (20-60 Bytes)</span>
              <span className="text-[10px] text-[#7F8996] font-sans">RFC 791</span>
            </h4>
            <div className="space-y-1 text-[#D1D5DB] font-mono text-[11px]">
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Version (4 bits):</span>
                <span className="font-bold text-[#F3F4F6]">4 (IPv4)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">IHL (4 bits):</span>
                <span>Header length in 32-bit words (5 = 20B)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Total Length (16 bits):</span>
                <span>Length of entire packet (header + data)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Time to Live (8 bits):</span>
                <span>Hop limit counter (decremented by routers)</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[#7F8996] font-sans">Protocol (8 bits):</span>
                <span className="text-[#60A5FA] font-bold">6 = TCP, 17 = UDP, 1 = ICMP</span>
              </div>
            </div>
          </div>

          {/* TCP Header */}
          <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] space-y-2">
            <h4 className="font-bold text-[#A78BFA] flex justify-between border-b border-[#363B42] pb-1.5">
              <span>TCP Header (20-60 Bytes)</span>
              <span className="text-[10px] text-[#7F8996] font-sans">RFC 9293</span>
            </h4>
            <div className="space-y-1 text-[#D1D5DB] font-mono text-[11px]">
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Source & Dest Ports:</span>
                <span className="font-bold text-[#F3F4F6]">16 bits each (0 - 65535)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Sequence Number (32 bits):</span>
                <span>Byte sequence number in stream</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Acknowledgment Number:</span>
                <span>Next byte expected from sender</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#363B42]">
                <span className="text-[#7F8996] font-sans">Control Flags (9 bits):</span>
                <span className="text-[#60A5FA] font-bold">URG, ACK, PSH, RST, SYN, FIN</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[#7F8996] font-sans">Window Size (16 bits):</span>
                <span>Flow control receive buffer capacity</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Viva Voce Q&A Section */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex items-center space-x-2 text-sm font-bold text-[#F3F4F6]">
          <HelpCircle className="w-5 h-5 text-[#34D399]" />
          <span>4. Computer Networks Viva Voce / Laboratory Examination Questions</span>
        </div>

        <p className="text-[#A1A8B3]">
          Frequently asked viva and oral evaluation questions designed for Computer Networks project defense:
        </p>

        <div className="space-y-2.5">
          {VIVA_QUESTIONS.map((faq, idx) => {
            const isOpen = openFaq === idx;
            return (
              <div key={idx} className="bg-[#202429] border border-[#454B53] rounded-xl overflow-hidden">
                <button
                  onClick={() => setOpenFaq(isOpen ? null : idx)}
                  className="w-full p-3.5 flex items-center justify-between text-left font-semibold text-[#F3F4F6] hover:text-[#60A5FA] transition-colors cursor-pointer"
                >
                  <span className="flex items-center space-x-2">
                    <span className="font-mono text-[#60A5FA] font-bold">Q{idx + 1}:</span>
                    <span>{faq.q}</span>
                  </span>
                  {isOpen ? <ChevronDown className="w-4 h-4 text-[#60A5FA]" /> : <ChevronRight className="w-4 h-4 text-[#7F8996]" />}
                </button>

                {isOpen && (
                  <div className="px-4 pb-3.5 pt-2 text-[#D1D5DB] border-t border-[#363B42] leading-relaxed font-sans bg-[#191C20] whitespace-pre-line">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
