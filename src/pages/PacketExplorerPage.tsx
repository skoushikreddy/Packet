/**
 * NetScope — Deep Packet Explorer (Graphite Minimal Theme)
 * Search, sorting, protocol tabs, pagination, size filters, and full dissection drawer.
 */

import React, { useState, useMemo } from 'react';
import { 
  Search, 
  ArrowUpDown, 
  ChevronLeft, 
  ChevronRight, 
  X
} from 'lucide-react';
import { Packet } from '../types/packet';
import { PacketTable } from '../components/PacketTable';
import { PacketInspector } from '../components/PacketInspector';

interface PacketExplorerPageProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  onSelectPacket: (pkt: Packet) => void;
}

export const PacketExplorerPage: React.FC<PacketExplorerPageProps> = ({
  packets,
  selectedPacket,
  onSelectPacket,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProto, setSelectedProto] = useState<string>('ALL');
  const [directionFilter, setDirectionFilter] = useState<'ALL' | 'INCOMING' | 'OUTGOING'>('ALL');
  const [minSize] = useState<number>(0);
  const [maxSize] = useState<number>(2000);
  const [sortBy, setSortBy] = useState<'id' | 'timestamp' | 'length' | 'protocol'>('id');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);
  const [showDrawer, setShowDrawer] = useState<boolean>(true);

  // Protocols list
  const PROTOCOLS = ['ALL', 'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'TLS'];

  // Filter and sort
  const filteredAndSortedPackets = useMemo(() => {
    let result = [...packets];

    // 1. Text search across IP, Info, Payload
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(p => 
        p.srcIp.toLowerCase().includes(q) ||
        p.dstIp.toLowerCase().includes(q) ||
        p.info.toLowerCase().includes(q) ||
        (p.srcPort && String(p.srcPort).includes(q)) ||
        (p.dstPort && String(p.dstPort).includes(q)) ||
        (p.payloadAscii && p.payloadAscii.toLowerCase().includes(q))
      );
    }

    // 2. Protocol filter
    if (selectedProto !== 'ALL') {
      result = result.filter(p => {
        if (selectedProto === 'TCP') return p.protocol === 'TCP' || !!p.tcp;
        if (selectedProto === 'UDP') return p.protocol === 'UDP' || !!p.udp;
        if (selectedProto === 'ICMP') return p.protocol === 'ICMP' || !!p.icmp;
        if (selectedProto === 'ARP') return p.protocol === 'ARP' || !!p.arp;
        if (selectedProto === 'DNS') return p.protocol === 'DNS' || !!p.dns;
        if (selectedProto === 'HTTP') return p.protocol === 'HTTP' || !!p.http;
        if (selectedProto === 'TLS') return p.protocol === 'TLS' || !!p.tls;
        return p.protocol === selectedProto;
      });
    }

    // 3. Direction
    if (directionFilter !== 'ALL') {
      result = result.filter(p => p.direction === directionFilter);
    }

    // 4. Packet size
    result = result.filter(p => p.length >= minSize && p.length <= maxSize);

    // 5. Sort
    result.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'id') comparison = a.id - b.id;
      else if (sortBy === 'timestamp') comparison = a.timestamp - b.timestamp;
      else if (sortBy === 'length') comparison = a.length - b.length;
      else if (sortBy === 'protocol') comparison = a.protocol.localeCompare(b.protocol);

      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return result;
  }, [packets, searchQuery, selectedProto, directionFilter, minSize, maxSize, sortBy, sortOrder]);

  // Pagination calculation
  const totalItems = filteredAndSortedPackets.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const paginatedPackets = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAndSortedPackets.slice(start, start + pageSize);
  }, [filteredAndSortedPackets, currentPage, pageSize]);

  const handleSelectPkt = (pkt: Packet) => {
    onSelectPacket(pkt);
    setShowDrawer(true);
  };

  return (
    <div className="h-[calc(100vh-8.5rem)] flex flex-col space-y-3">
      {/* Search & Control Filter Bar */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 space-y-3 shadow-xs shrink-0">
        <div className="flex flex-col md:flex-row items-center gap-3">
          {/* Search Input */}
          <div className="relative flex-1 w-full flex items-center bg-[#202429] border border-[#454B53] rounded-lg px-3 py-1.5 focus-within:border-[#60A5FA]">
            <Search className="w-4 h-4 text-[#7F8996] mr-2 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search by IP, port, payload content, or keywords..."
              className="w-full bg-transparent text-xs text-[#F3F4F6] placeholder-[#7F8996] font-mono outline-none"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery('')} className="text-[#7F8996] hover:text-[#D1D5DB] p-1 cursor-pointer">
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Direction Filter */}
          <div className="flex items-center space-x-1 bg-[#202429] border border-[#454B53] rounded-lg p-1 text-xs">
            <button
              onClick={() => { setDirectionFilter('ALL'); setCurrentPage(1); }}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                directionFilter === 'ALL' ? 'bg-[#30353B] border border-[#454B53] text-[#F3F4F6] font-semibold' : 'text-[#A1A8B3] hover:text-[#F3F4F6]'
              }`}
            >
              All
            </button>
            <button
              onClick={() => { setDirectionFilter('INCOMING'); setCurrentPage(1); }}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                directionFilter === 'INCOMING' ? 'bg-[#30353B] border border-[#454B53] text-[#34D399] font-semibold' : 'text-[#A1A8B3] hover:text-[#F3F4F6]'
              }`}
            >
              Incoming
            </button>
            <button
              onClick={() => { setDirectionFilter('OUTGOING'); setCurrentPage(1); }}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                directionFilter === 'OUTGOING' ? 'bg-[#30353B] border border-[#454B53] text-[#60A5FA] font-semibold' : 'text-[#A1A8B3] hover:text-[#F3F4F6]'
              }`}
            >
              Outgoing
            </button>
          </div>

          {/* Sort By Dropdown */}
          <div className="flex items-center space-x-2 bg-[#202429] border border-[#454B53] rounded-lg px-2.5 py-1 text-xs text-[#D1D5DB]">
            <ArrowUpDown className="w-3.5 h-3.5 text-[#7F8996]" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-transparent text-[#D1D5DB] outline-none text-xs cursor-pointer font-medium"
            >
              <option value="id" className="bg-[#24282D] text-[#D1D5DB]">Packet No.</option>
              <option value="timestamp" className="bg-[#24282D] text-[#D1D5DB]">Timestamp</option>
              <option value="length" className="bg-[#24282D] text-[#D1D5DB]">Length</option>
              <option value="protocol" className="bg-[#24282D] text-[#D1D5DB]">Protocol</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              className="text-[10px] uppercase font-bold text-[#60A5FA] px-1 hover:underline cursor-pointer"
            >
              {sortOrder}
            </button>
          </div>
        </div>

        {/* Protocol Pills & Size Filter */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-[#363B42]">
          {/* Protocol Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            {PROTOCOLS.map((proto) => (
              <button
                key={proto}
                onClick={() => {
                  setSelectedProto(proto);
                  setCurrentPage(1);
                }}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold tracking-wide transition-colors cursor-pointer ${
                  selectedProto === proto
                    ? 'bg-[#60A5FA] text-[#191C20] font-bold'
                    : 'bg-[#202429] text-[#A1A8B3] hover:text-[#F3F4F6] hover:bg-[#383E45] border border-[#454B53]'
                }`}
              >
                {proto}
              </button>
            ))}
          </div>

          {/* Match Count & Page Size */}
          <div className="flex items-center space-x-3 text-xs text-[#A1A8B3]">
            <span>
              Matches: <strong className="text-[#F3F4F6]">{filteredAndSortedPackets.length}</strong> of {packets.length}
            </span>
            <div className="flex items-center space-x-1">
              <span>Per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="bg-[#202429] border border-[#454B53] text-[#D1D5DB] rounded px-1.5 py-0.5 text-xs outline-none"
              >
                <option value={25} className="bg-[#24282D]">25</option>
                <option value={50} className="bg-[#24282D]">50</option>
                <option value={100} className="bg-[#24282D]">100</option>
                <option value={200} className="bg-[#24282D]">200</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Main Table + Dissection Drawer */}
      <div className="flex-1 flex gap-3 overflow-hidden">
        {/* Table View */}
        <div className={`h-full overflow-hidden flex flex-col justify-between ${showDrawer && selectedPacket ? 'w-full lg:w-3/5' : 'w-full'}`}>
          <div className="flex-1 overflow-hidden">
            <PacketTable
              packets={paginatedPackets}
              selectedPacket={selectedPacket}
              onSelectPacket={handleSelectPkt}
            />
          </div>

          {/* Pagination Toolbar */}
          <div className="bg-[#292E34] border border-[#454B53] rounded-xl px-4 py-2 mt-2 flex items-center justify-between text-xs text-[#A1A8B3] shrink-0 shadow-xs">
            <div>
              Showing {totalItems > 0 ? (currentPage - 1) * pageSize + 1 : 0} - {Math.min(currentPage * pageSize, totalItems)} of {totalItems} packets
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="p-1 rounded bg-[#202429] hover:bg-[#383E45] border border-[#454B53] disabled:opacity-40 text-[#D1D5DB] transition-colors cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="font-mono text-[#F3F4F6] font-semibold">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="p-1 rounded bg-[#202429] hover:bg-[#383E45] border border-[#454B53] disabled:opacity-40 text-[#D1D5DB] transition-colors cursor-pointer"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Packet Inspector Drawer */}
        {showDrawer && selectedPacket && (
          <div className="hidden lg:flex w-2/5 h-full overflow-hidden">
            <PacketInspector
              packet={selectedPacket}
              onClose={() => setShowDrawer(false)}
            />
          </div>
        )}
      </div>
    </div>
  );
};
