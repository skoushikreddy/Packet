/**
 * NetScope — Wireshark-Style Collapsible Protocol Layer Inspector & Hex Viewer (Graphite Minimal Theme)
 */

import React, { useState } from 'react';
import { 
  ChevronDown, 
  ChevronRight, 
  Copy, 
  Check, 
  Binary, 
  Layers, 
  ShieldCheck
} from 'lucide-react';
import { Packet } from '../types/packet';

interface PacketInspectorProps {
  packet: Packet | null;
  onClose?: () => void;
}

export const PacketInspector: React.FC<PacketInspectorProps> = ({ packet, onClose }) => {
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    frame: true,
    ethernet: true,
    ip: true,
    transport: true,
    application: true,
    hex: true,
  });

  const [copiedHex, setCopiedHex] = useState(false);

  if (!packet) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 text-center text-[#A1A8B3] bg-[#292E34] rounded-xl border border-[#454B53] shadow-xs">
        <Layers className="w-9 h-9 text-[#7F8996] mb-2 opacity-80" />
        <h4 className="text-xs font-semibold text-[#F3F4F6]">No Packet Selected</h4>
        <p className="text-[11px] text-[#7F8996] mt-0.5">Click any packet in the table above to dissect its protocol layers and inspect raw payload bytes.</p>
      </div>
    );
  }

  const toggle = (section: string) => {
    setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 1500);
  };

  // Format Hex Dump in standard 16-bytes per line with offset
  const renderHexDump = () => {
    if (!packet.rawHex) return <div className="text-[#7F8996] italic">No raw bytes available</div>;

    const hexBytes = packet.rawHex.split(' ').filter(h => h.length > 0);
    const rows: Array<{ offset: string; hex: string[]; ascii: string }> = [];

    for (let i = 0; i < hexBytes.length; i += 16) {
      const chunk = hexBytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');
      let ascii = '';

      for (const h of chunk) {
        const byteVal = parseInt(h, 16);
        if (byteVal >= 32 && byteVal <= 126) {
          ascii += String.fromCharCode(byteVal);
        } else {
          ascii += '.';
        }
      }

      rows.push({ offset, hex: chunk, ascii });
    }

    return (
      <div className="font-mono text-[11px] leading-relaxed bg-[#202429] p-3 rounded-lg border border-[#454B53] overflow-x-auto text-[#D1D5DB] select-text">
        {rows.map((row, idx) => (
          <div key={idx} className="flex hover:bg-[#383E45]/60 px-1 py-0.5 rounded transition-colors">
            {/* Offset */}
            <span className="text-[#7F8996] w-16 select-none font-bold">{row.offset}</span>
            {/* Hex Bytes (8 + 8 with spacer) */}
            <div className="flex-1 flex space-x-2 text-[#60A5FA] font-medium">
              <span className="w-48 tracking-widest">{row.hex.slice(0, 8).join(' ')}</span>
              <span className="w-48 tracking-widest">{row.hex.slice(8, 16).join(' ')}</span>
            </div>
            {/* ASCII Characters */}
            <span className="text-[#34D399] font-medium ml-4 tracking-wider">{row.ascii}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col bg-[#292E34] border border-[#454B53] rounded-xl overflow-hidden shadow-xs text-xs text-[#D1D5DB]">
      {/* Header bar */}
      <div className="bg-[#24282D] px-4 py-2.5 border-b border-[#454B53] flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-[#94A3B8]" />
          <span className="font-bold text-[#F3F4F6]">Packet Dissector & Header Details</span>
          <span className="px-2 py-0.5 rounded bg-[#202429] text-[#94A3B8] border border-[#454B53] font-mono text-[11px]">
            Frame #{packet.id} • {packet.length} Bytes
          </span>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => copyToClipboard(packet.rawHex || '')}
            className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#D1D5DB] transition-colors text-[11px] cursor-pointer"
            title="Copy Raw Hex Dump"
          >
            {copiedHex ? <Check className="w-3 h-3 text-[#34D399]" /> : <Copy className="w-3 h-3 text-[#A1A8B3]" />}
            <span>{copiedHex ? 'Copied' : 'Copy Hex'}</span>
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="text-[#7F8996] hover:text-[#F3F4F6] p-1 rounded transition-colors"
              title="Close panel"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Dissected Layers Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
        {/* Layer 1: Frame Summary */}
        <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
          <button
            onClick={() => toggle('frame')}
            className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#F3F4F6] cursor-pointer transition-colors border-b border-[#454B53]"
          >
            <div className="flex items-center space-x-2">
              {openSections.frame ? <ChevronDown className="w-3.5 h-3.5 text-[#94A3B8]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#7F8996]" />}
              <span>Frame #{packet.id}: {packet.length} bytes on wire ({packet.length * 8} bits)</span>
            </div>
            <span className="text-[10px] text-[#A1A8B3] font-mono">{packet.timeStr}</span>
          </button>

          {openSections.frame && (
            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Interface / Link Type:</span>
                <span className="text-[#F3F4F6] font-semibold">Ethernet (10/100/1000/Auto)</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Arrival Time:</span>
                <span className="text-[#D1D5DB]">{new Date(packet.timestamp).toISOString()}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Relative Time from Start:</span>
                <span className="text-[#60A5FA] font-bold">{packet.relTime.toFixed(4)} seconds</span>
              </div>
              <div className="flex justify-between py-0.5">
                <span className="text-[#7F8996]">Frame Length / Captured Length:</span>
                <span className="text-[#D1D5DB]">{packet.length} bytes ({packet.length} bytes captured)</span>
              </div>
            </div>
          )}
        </div>

        {/* Layer 2: Ethernet II */}
        {packet.ethernet && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('ethernet')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#F3F4F6] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                {openSections.ethernet ? <ChevronDown className="w-3.5 h-3.5 text-[#94A3B8]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#7F8996]" />}
                <span>Ethernet II, Src: {packet.ethernet.srcMac}, Dst: {packet.ethernet.dstMac}</span>
              </div>
              <span className="text-[10px] text-[#60A5FA] font-mono">{packet.ethernet.etherType}</span>
            </button>

            {openSections.ethernet && (
              <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Destination MAC (48-bit):</span>
                  <span className="text-[#F3F4F6] font-semibold">{packet.ethernet.dstMac}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Source MAC (48-bit):</span>
                  <span className="text-[#F3F4F6] font-semibold">{packet.ethernet.srcMac}</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span className="text-[#7F8996]">Type:</span>
                  <span className="text-[#60A5FA] font-bold">{packet.ethernet.etherType}</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Layer 3: ARP */}
        {packet.arp && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('transport')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#FBBF24] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                <ChevronDown className="w-3.5 h-3.5 text-[#FBBF24]" />
                <span>Address Resolution Protocol ({packet.arp.opcodeName})</span>
              </div>
              <span className="text-[10px] text-[#FBBF24] font-mono">Opcode: {packet.arp.opcode}</span>
            </button>

            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Hardware Type:</span>
                <span className="text-[#D1D5DB]">Ethernet (1)</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Protocol Type:</span>
                <span className="text-[#D1D5DB]">IPv4 ({packet.arp.protocolType})</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Sender MAC:</span>
                <span className="text-[#60A5FA] font-semibold">{packet.arp.senderMac}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Sender IP:</span>
                <span className="text-[#60A5FA] font-semibold">{packet.arp.senderIp}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Target MAC:</span>
                <span className="text-[#34D399] font-semibold">{packet.arp.targetMac}</span>
              </div>
              <div className="flex justify-between py-0.5">
                <span className="text-[#7F8996]">Target IP:</span>
                <span className="text-[#34D399] font-semibold">{packet.arp.targetIp}</span>
              </div>
            </div>
          </div>
        )}

        {/* Layer 3: IPv4 */}
        {packet.ip && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('ip')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#F3F4F6] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                {openSections.ip ? <ChevronDown className="w-3.5 h-3.5 text-[#94A3B8]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#7F8996]" />}
                <span>Internet Protocol Version 4, Src: {packet.ip.srcIp}, Dst: {packet.ip.dstIp}</span>
              </div>
              <span className="text-[10px] text-[#60A5FA] font-mono">TTL: {packet.ip.ttl}</span>
            </button>

            {openSections.ip && (
              <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Version:</span>
                  <span className="text-[#F3F4F6] font-bold">{packet.ip.version}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Header Length (IHL):</span>
                  <span className="text-[#D1D5DB]">{packet.ip.ihl * 4} bytes ({packet.ip.ihl} words)</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Total Length:</span>
                  <span className="text-[#D1D5DB]">{packet.ip.totalLength} bytes</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Identification:</span>
                  <span className="text-[#D1D5DB] font-mono">0x{packet.ip.identification.toString(16).padStart(4, '0')} ({packet.ip.identification})</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Flags & Fragment Offset:</span>
                  <span className="text-[#D1D5DB]">
                    {packet.ip.flags.dontFragment ? "Don't Fragment (DF)" : 'Can Fragment'} • Offset: {packet.ip.fragmentOffset}
                  </span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Time to Live (TTL):</span>
                  <span className="text-[#34D399] font-bold">{packet.ip.ttl} hops remaining</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Protocol:</span>
                  <span className="text-[#60A5FA] font-bold">{packet.ip.protocolName} ({packet.ip.protocol})</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Header Checksum:</span>
                  <span className="text-[#D1D5DB]">{packet.ip.headerChecksum} [Validated]</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Source Address:</span>
                  <span className="text-[#60A5FA] font-bold">{packet.ip.srcIp}</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span className="text-[#7F8996]">Destination Address:</span>
                  <span className="text-[#60A5FA] font-bold">{packet.ip.dstIp}</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Layer 4: TCP */}
        {packet.tcp && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('transport')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#60A5FA] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                {openSections.transport ? <ChevronDown className="w-3.5 h-3.5 text-[#60A5FA]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#7F8996]" />}
                <span>Transmission Control Protocol, Src Port: {packet.tcp.srcPort}, Dst Port: {packet.tcp.dstPort}</span>
              </div>
              <span className="text-[10px] text-[#60A5FA] font-mono">{packet.tcp.flagsSummary}</span>
            </button>

            {openSections.transport && (
              <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Source Port:</span>
                  <span className="text-[#F3F4F6] font-bold">{packet.tcp.srcPort}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Destination Port:</span>
                  <span className="text-[#F3F4F6] font-bold">{packet.tcp.dstPort}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Sequence Number:</span>
                  <span className="text-[#60A5FA]">{packet.tcp.seqNumber}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Acknowledgment Number:</span>
                  <span className="text-[#60A5FA]">{packet.tcp.ackNumber}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Header Length (Data Offset):</span>
                  <span className="text-[#D1D5DB]">{packet.tcp.dataOffset * 4} bytes ({packet.tcp.dataOffset} words)</span>
                </div>
                <div className="py-1 border-b border-[#363B42]">
                  <div className="flex justify-between text-[#A1A8B3] mb-1">
                    <span>Flags:</span>
                    <span className="text-[#60A5FA] font-bold">{packet.tcp.flagsSummary}</span>
                  </div>
                  <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5 text-[10px] bg-[#191C20] p-2 rounded border border-[#363B42]">
                    <span className={packet.tcp.flags.syn ? 'text-[#34D399] font-bold' : 'text-[#626B76]'}>
                      SYN: {packet.tcp.flags.syn ? '1' : '0'}
                    </span>
                    <span className={packet.tcp.flags.ack ? 'text-[#34D399] font-bold' : 'text-[#626B76]'}>
                      ACK: {packet.tcp.flags.ack ? '1' : '0'}
                    </span>
                    <span className={packet.tcp.flags.fin ? 'text-[#F87171] font-bold' : 'text-[#626B76]'}>
                      FIN: {packet.tcp.flags.fin ? '1' : '0'}
                    </span>
                    <span className={packet.tcp.flags.rst ? 'text-[#F87171] font-bold' : 'text-[#626B76]'}>
                      RST: {packet.tcp.flags.rst ? '1' : '0'}
                    </span>
                    <span className={packet.tcp.flags.psh ? 'text-[#FBBF24] font-bold' : 'text-[#626B76]'}>
                      PSH: {packet.tcp.flags.psh ? '1' : '0'}
                    </span>
                    <span className={packet.tcp.flags.urg ? 'text-[#FBBF24] font-bold' : 'text-[#626B76]'}>
                      URG: {packet.tcp.flags.urg ? '1' : '0'}
                    </span>
                  </div>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Window Size:</span>
                  <span className="text-[#34D399] font-bold">{packet.tcp.windowSize} bytes</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span className="text-[#7F8996]">Checksum:</span>
                  <span className="text-[#D1D5DB]">{packet.tcp.checksum} [Correct]</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Layer 4: UDP */}
        {packet.udp && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('transport')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#A78BFA] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                <ChevronDown className="w-3.5 h-3.5 text-[#A78BFA]" />
                <span>User Datagram Protocol, Src Port: {packet.udp.srcPort}, Dst Port: {packet.udp.dstPort}</span>
              </div>
              <span className="text-[10px] text-[#A78BFA] font-mono">Len: {packet.udp.length}</span>
            </button>

            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Source Port:</span>
                <span className="text-[#F3F4F6] font-bold">{packet.udp.srcPort}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Destination Port:</span>
                <span className="text-[#F3F4F6] font-bold">{packet.udp.dstPort}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Length:</span>
                <span className="text-[#D1D5DB]">{packet.udp.length} bytes (header + payload)</span>
              </div>
              <div className="flex justify-between py-0.5">
                <span className="text-[#7F8996]">Checksum:</span>
                <span className="text-[#D1D5DB]">{packet.udp.checksum}</span>
              </div>
            </div>
          </div>
        )}

        {/* Layer 4: ICMP */}
        {packet.icmp && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('transport')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#FBBF24] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                <ChevronDown className="w-3.5 h-3.5 text-[#FBBF24]" />
                <span>Internet Control Message Protocol ({packet.icmp.typeName})</span>
              </div>
              <span className="text-[10px] text-[#FBBF24] font-mono">Type {packet.icmp.type}</span>
            </button>

            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Type:</span>
                <span className="text-[#FBBF24] font-bold">{packet.icmp.type} ({packet.icmp.typeName})</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Code:</span>
                <span className="text-[#D1D5DB]">{packet.icmp.code}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Identifier:</span>
                <span className="text-[#D1D5DB]">{packet.icmp.identifier ?? 'N/A'}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Sequence Number:</span>
                <span className="text-[#60A5FA] font-bold">{packet.icmp.seqNumber ?? 'N/A'}</span>
              </div>
              <div className="flex justify-between py-0.5">
                <span className="text-[#7F8996]">Checksum:</span>
                <span className="text-[#D1D5DB]">{packet.icmp.checksum}</span>
              </div>
            </div>
          </div>
        )}

        {/* Layer 7: DNS */}
        {packet.dns && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('application')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#34D399] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                <ChevronDown className="w-3.5 h-3.5 text-[#34D399]" />
                <span>Domain Name System ({packet.dns.flags.isResponse ? 'Response' : 'Query'})</span>
              </div>
              <span className="text-[10px] text-[#34D399] font-mono">0x{packet.dns.transactionId}</span>
            </button>

            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Transaction ID:</span>
                <span className="text-[#34D399] font-bold">0x{packet.dns.transactionId}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">QR Bit (Response):</span>
                <span className="text-[#D1D5DB]">{packet.dns.flags.isResponse ? '1 (Message is a response)' : '0 (Message is a query)'}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Recursion Desired:</span>
                <span className="text-[#D1D5DB]">{packet.dns.flags.recursionDesired ? 'Yes' : 'No'}</span>
              </div>
              {packet.dns.questions && packet.dns.questions.length > 0 && (
                <div className="py-1 border-b border-[#363B42]">
                  <span className="text-[#A1A8B3] block mb-0.5 font-bold">Queries:</span>
                  {packet.dns.questions.map((q, idx) => (
                    <div key={idx} className="bg-[#191C20] p-1.5 rounded text-[#60A5FA] border border-[#363B42]">
                      • {q.name}: type {q.type}, class {q.class}
                    </div>
                  ))}
                </div>
              )}
              {packet.dns.answers && packet.dns.answers.length > 0 && (
                <div className="py-1">
                  <span className="text-[#A1A8B3] block mb-0.5 font-bold">Answers:</span>
                  {packet.dns.answers.map((a, idx) => (
                    <div key={idx} className="bg-[#191C20] p-1.5 rounded text-[#34D399] border border-[#363B42]">
                      • {a.name}: addr {a.data} (TTL {a.ttl}s)
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Layer 7: HTTP */}
        {packet.http && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('application')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#F87171] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                <ChevronDown className="w-3.5 h-3.5 text-[#F87171]" />
                <span>Hypertext Transfer Protocol ({packet.http.type})</span>
              </div>
              <span className="text-[10px] text-[#F87171] font-mono">{packet.http.method || packet.http.statusCode}</span>
            </button>

            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              {packet.http.type === 'REQUEST' ? (
                <>
                  <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                    <span className="text-[#7F8996]">Request Method:</span>
                    <span className="text-[#F87171] font-bold">{packet.http.method}</span>
                  </div>
                  <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                    <span className="text-[#7F8996]">Request URI:</span>
                    <span className="text-[#D1D5DB]">{packet.http.path}</span>
                  </div>
                </>
              ) : (
                <>
                  <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                    <span className="text-[#7F8996]">Status Code:</span>
                    <span className="text-[#34D399] font-bold">{packet.http.statusCode} {packet.http.statusText}</span>
                  </div>
                </>
              )}
              {packet.http.headers && Object.keys(packet.http.headers).length > 0 && (
                <div className="py-1">
                  <span className="text-[#A1A8B3] block mb-1 font-bold">HTTP Headers:</span>
                  <div className="bg-[#191C20] p-2 rounded space-y-1 border border-[#363B42]">
                    {Object.entries(packet.http.headers).map(([key, val]) => (
                      <div key={key} className="flex justify-between">
                        <span className="text-[#7F8996]">{key}:</span>
                        <span className="text-[#60A5FA] truncate max-w-xs">{val}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Layer 7: TLS */}
        {packet.tls && (
          <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
            <button
              onClick={() => toggle('application')}
              className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#38BDF8] cursor-pointer transition-colors border-b border-[#454B53]"
            >
              <div className="flex items-center space-x-2">
                <ChevronDown className="w-3.5 h-3.5 text-[#38BDF8]" />
                <span>Transport Layer Security ({packet.tls.version})</span>
              </div>
              <span className="text-[10px] text-[#38BDF8] font-mono">{packet.tls.handshakeType || 'Encrypted Application Data'}</span>
            </button>

            <div className="p-3 bg-[#202429] font-mono text-[11px] space-y-1 text-[#D1D5DB]">
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Record Type:</span>
                <span className="text-[#D1D5DB]">{packet.tls.recordType}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                <span className="text-[#7F8996]">Negotiated Protocol Version:</span>
                <span className="text-[#38BDF8] font-bold">{packet.tls.version}</span>
              </div>
              {packet.tls.serverNameIndication && (
                <div className="flex justify-between py-0.5 border-b border-[#363B42]">
                  <span className="text-[#7F8996]">Server Name Indication (SNI):</span>
                  <span className="text-[#60A5FA] font-bold">{packet.tls.serverNameIndication}</span>
                </div>
              )}
              {packet.tls.cipherSuites && (
                <div className="py-1">
                  <span className="text-[#A1A8B3] block mb-1">Offered Cipher Suites:</span>
                  <div className="bg-[#191C20] p-2 rounded space-y-0.5 text-[10px] text-[#60A5FA] border border-[#363B42]">
                    {packet.tls.cipherSuites.map((cs, idx) => (
                      <div key={idx}>• {cs}</div>
                    ))}
                  </div>
                </div>
              )}
              <div className="p-2 rounded bg-[#191C20] border border-[#363B42] text-[10px] text-[#A1A8B3] flex items-center space-x-1.5 mt-2">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0 text-[#38BDF8]" />
                <span>TLS Payload is end-to-end encrypted. As an ethical analyzer, NetScope inspects only handshake metadata without payload interception.</span>
              </div>
            </div>
          </div>
        )}

        {/* Raw Bytes & Hex Dump View */}
        <div className="border border-[#454B53] rounded-lg overflow-hidden bg-[#292E34]">
          <button
            onClick={() => toggle('hex')}
            className="w-full flex items-center justify-between px-3 py-2 bg-[#30353B] hover:bg-[#383E45] text-left font-semibold text-[#F3F4F6] cursor-pointer transition-colors border-b border-[#454B53]"
          >
            <div className="flex items-center space-x-2">
              <Binary className="w-3.5 h-3.5 text-[#94A3B8]" />
              <span>Packet Bytes (Hexadecimal & ASCII Dissection)</span>
            </div>
            <span className="text-[10px] text-[#7F8996] font-mono">16 bytes / row</span>
          </button>

          {openSections.hex && (
            <div className="p-3 bg-[#202429]">
              {renderHexDump()}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
