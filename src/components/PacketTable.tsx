/**
 * NetScope — Interactive Packet Table (Graphite Minimal Theme)
 * High-performance virtualized packet list with graphite surfaces and balanced protocol badges.
 */

import React from 'react';
import { 
  ArrowUpRight, 
  ArrowDownLeft, 
  Layers, 
  ChevronRight
} from 'lucide-react';
import { Packet, ProtocolType } from '../types/packet';

interface PacketTableProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  onFilterByIp?: (ip: string) => void;
  onFilterByProtocol?: (proto: string) => void;
}

export const PacketTable: React.FC<PacketTableProps> = ({
  packets,
  selectedPacket,
  onSelectPacket,
  onFilterByProtocol,
}) => {
  const getProtocolBadge = (protocol: ProtocolType) => {
    switch (protocol) {
      case 'TCP':
        return 'bg-[#60A5FA]/15 text-[#60A5FA] border-[#60A5FA]/30 hover:bg-[#60A5FA]/25';
      case 'UDP':
        return 'bg-[#A78BFA]/15 text-[#A78BFA] border-[#A78BFA]/30 hover:bg-[#A78BFA]/25';
      case 'ICMP':
        return 'bg-[#FBBF24]/15 text-[#FBBF24] border-[#FBBF24]/30 hover:bg-[#FBBF24]/25';
      case 'ARP':
        return 'bg-[#A1A8B3]/15 text-[#A1A8B3] border-[#A1A8B3]/30 hover:bg-[#A1A8B3]/25';
      case 'DNS':
        return 'bg-[#34D399]/15 text-[#34D399] border-[#34D399]/30 hover:bg-[#34D399]/25';
      case 'HTTP':
        return 'bg-[#F87171]/15 text-[#F87171] border-[#F87171]/30 hover:bg-[#F87171]/25';
      case 'TLS':
      case 'HTTPS':
        return 'bg-[#38BDF8]/15 text-[#38BDF8] border-[#38BDF8]/30 hover:bg-[#38BDF8]/25';
      default:
        return 'bg-[#202429] text-[#A1A8B3] border-[#454B53] hover:bg-[#383E45]';
    }
  };

  if (packets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center text-[#A1A8B3] bg-[#292E34] rounded-xl border border-[#454B53] shadow-xs">
        <Layers className="w-9 h-9 text-[#7F8996] mb-3" />
        <h4 className="text-sm font-semibold text-[#F3F4F6]">No Packets in View</h4>
        <p className="text-xs text-[#A1A8B3] mt-1 max-w-sm">
          Start a live capture, load an academic sample trace, or adjust your display filter to inspect network traffic.
        </p>
      </div>
    );
  }

  return (
    <div className="w-full overflow-hidden rounded-xl border border-[#454B53] bg-[#292E34] shadow-xs flex flex-col h-full">
      <div className="overflow-x-auto flex-1 custom-scrollbar">
        <table className="w-full text-left border-collapse text-xs select-none">
          {/* Header */}
          <thead className="bg-[#202429] text-[#A1A8B3] font-semibold uppercase tracking-wider text-[10px] border-b border-[#454B53] sticky top-0 z-10">
            <tr>
              <th className="py-2.5 px-3 w-16 text-center">No.</th>
              <th className="py-2.5 px-3 w-28">Time</th>
              <th className="py-2.5 px-3 w-40">Source IP</th>
              <th className="py-2.5 px-3 w-40">Destination IP</th>
              <th className="py-2.5 px-3 w-24 text-center">Protocol</th>
              <th className="py-2.5 px-3 w-20 text-right">Length</th>
              <th className="py-2.5 px-3">Info</th>
            </tr>
          </thead>

          {/* Body */}
          <tbody className="divide-y divide-[#363B42] font-mono">
            {packets.map((pkt, idx) => {
              const isSelected = selectedPacket?.id === pkt.id;
              const isOutgoing = pkt.direction === 'OUTGOING';

              return (
                <tr
                  key={pkt.id}
                  onClick={() => onSelectPacket(pkt)}
                  className={`transition-colors cursor-pointer group ${
                    isSelected
                      ? 'bg-[#30353B] text-[#F3F4F6] border-l-2 border-[#60A5FA]'
                      : idx % 2 === 1
                      ? 'bg-[#24282D] hover:bg-[#383E45] text-[#D1D5DB]'
                      : 'bg-[#292E34] hover:bg-[#383E45] text-[#D1D5DB]'
                  }`}
                >
                  {/* Packet Number */}
                  <td className="py-2.5 px-3 text-center text-[#7F8996] font-semibold group-hover:text-[#D1D5DB]">
                    {pkt.id}
                  </td>

                  {/* Timestamp */}
                  <td className="py-2.5 px-3 text-[#A1A8B3] text-[11px] whitespace-nowrap">
                    {pkt.timeStr}
                  </td>

                  {/* Source IP */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <div className="flex items-center space-x-1.5">
                      {isOutgoing ? (
                        <span title="Outgoing traffic">
                          <ArrowUpRight className="w-3.5 h-3.5 text-[#60A5FA] shrink-0" />
                        </span>
                      ) : (
                        <span title="Incoming traffic">
                          <ArrowDownLeft className="w-3.5 h-3.5 text-[#34D399] shrink-0" />
                        </span>
                      )}
                      <span className="font-semibold text-[#D1D5DB] group-hover:text-[#F3F4F6]">
                        {pkt.srcIp}
                      </span>
                      {pkt.srcPort && (
                        <span className="text-[#7F8996] text-[10px]">:{pkt.srcPort}</span>
                      )}
                    </div>
                  </td>

                  {/* Destination IP */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <div className="flex items-center space-x-1.5">
                      <span className="font-semibold text-[#D1D5DB] group-hover:text-[#F3F4F6]">
                        {pkt.dstIp}
                      </span>
                      {pkt.dstPort && (
                        <span className="text-[#7F8996] text-[10px]">:{pkt.dstPort}</span>
                      )}
                    </div>
                  </td>

                  {/* Protocol Badge */}
                  <td className="py-2.5 px-3 text-center whitespace-nowrap">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onFilterByProtocol?.(pkt.protocol);
                      }}
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold tracking-wide border cursor-pointer transition-colors ${getProtocolBadge(
                        pkt.protocol
                      )}`}
                      title={`Filter by ${pkt.protocol}`}
                    >
                      {pkt.protocol}
                    </button>
                  </td>

                  {/* Length */}
                  <td className="py-2.5 px-3 text-right text-[#A1A8B3] font-mono text-[11px] whitespace-nowrap">
                    {pkt.length} B
                  </td>

                  {/* Info description */}
                  <td className="py-2.5 px-3 text-[#D1D5DB] text-[11px] truncate max-w-md font-sans">
                    <div className="flex items-center justify-between">
                      <span className="truncate">{pkt.info}</span>
                      <ChevronRight className="w-3.5 h-3.5 text-[#7F8996] group-hover:text-[#F3F4F6] shrink-0 ml-2" />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
