/**
 * NetScope — Live Packet Capture Workstation (Graphite Minimal Theme)
 * Real-time packet capture, auto-scroll pause/resume, filter bar, and split-screen inspector.
 */

import React, { useState } from 'react';
import { 
  Play, 
  Square, 
  Pause, 
  PlayCircle, 
  Trash2, 
  Save, 
  Split 
} from 'lucide-react';
import { Packet } from '../types/packet';
import { FilterBar } from '../components/FilterBar';
import { PacketTable } from '../components/PacketTable';
import { PacketInspector } from '../components/PacketInspector';
import { filterPackets } from '../utils/filterEngine';

interface LiveCapturePageProps {
  packets: Packet[];
  isCapturing: boolean;
  onStartCapture: () => void;
  onStopCapture: () => void;
  onClearPackets: () => void;
  onSaveCapture: () => void;
  selectedPacket: Packet | null;
  onSelectPacket: (pkt: Packet) => void;
  selectedInterface: string;
}

export const LiveCapturePage: React.FC<LiveCapturePageProps> = ({
  packets,
  isCapturing,
  onStartCapture,
  onStopCapture,
  onClearPackets,
  onSaveCapture,
  selectedPacket,
  onSelectPacket,
  selectedInterface,
}) => {
  const [displayFilter, setDisplayFilter] = useState('');
  const [isPausedDisplay, setIsPausedDisplay] = useState(false);
  const [splitMode, setSplitMode] = useState<'vertical' | 'horizontal'>('vertical');

  // Filter packets according to current filter
  const filteredPackets = React.useMemo(() => {
    return filterPackets(packets, displayFilter);
  }, [packets, displayFilter]);

  const displayedPackets = filteredPackets;

  return (
    <div className="h-[calc(100vh-8.5rem)] flex flex-col space-y-3">
      {/* Workstation Control Ribbon */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shrink-0 shadow-xs">
        {/* Left Action Buttons */}
        <div className="flex items-center space-x-2">
          {!isCapturing ? (
            <button
              onClick={onStartCapture}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#34D399] hover:bg-[#10B981] active:bg-[#059669] text-[#191C20] transition-colors cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Start</span>
            </button>
          ) : (
            <button
              onClick={onStopCapture}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#F87171] hover:bg-[#EF4444] active:bg-[#DC2626] text-[#191C20] transition-colors cursor-pointer"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>Stop</span>
            </button>
          )}

          {/* Pause / Resume Display */}
          <button
            onClick={() => setIsPausedDisplay(!isPausedDisplay)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
              isPausedDisplay
                ? 'bg-[#FBBF24]/15 border-[#FBBF24]/40 text-[#FBBF24]'
                : 'bg-[#202429] hover:bg-[#383E45] border-[#454B53] text-[#D1D5DB]'
            }`}
            title={isPausedDisplay ? 'Resume auto-scrolling live packets' : 'Pause display to inspect current packets'}
          >
            {isPausedDisplay ? <PlayCircle className="w-3.5 h-3.5 text-[#FBBF24]" /> : <Pause className="w-3.5 h-3.5 text-[#A1A8B3]" />}
            <span>{isPausedDisplay ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>

          {/* Clear */}
          <button
            onClick={onClearPackets}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#D1D5DB] transition-colors cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5 text-[#A1A8B3]" />
            <span>Clear</span>
          </button>

          {/* Save Capture to History */}
          <button
            onClick={onSaveCapture}
            disabled={packets.length === 0}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#D1D5DB] disabled:opacity-40 transition-colors cursor-pointer"
            title="Save current packets to SQLite database"
          >
            <Save className="w-3.5 h-3.5 text-[#94A3B8]" />
            <span>Save Session</span>
          </button>
        </div>

        {/* Status indicator */}
        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-2 bg-[#202429] border border-[#454B53] px-3 py-1 rounded-lg">
            <span className="text-[10px] text-[#7F8996] uppercase font-semibold">IFACE:</span>
            <span className="font-mono font-semibold text-[#F3F4F6]">{selectedInterface}</span>
          </div>
          <div className="flex items-center space-x-2 bg-[#202429] border border-[#454B53] px-3 py-1 rounded-lg">
            <span className="text-[10px] text-[#7F8996] uppercase font-semibold">CAPTURED:</span>
            <span className="font-mono font-bold text-[#F3F4F6]">{packets.length.toLocaleString()}</span>
          </div>
          <button
            onClick={() => setSplitMode(splitMode === 'vertical' ? 'horizontal' : 'vertical')}
            className="p-1.5 rounded-lg bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#A1A8B3] hover:text-[#F3F4F6] transition-colors cursor-pointer"
            title={`Switch to ${splitMode === 'vertical' ? 'horizontal' : 'vertical'} split view`}
          >
            <Split className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="shrink-0">
        <FilterBar
          currentFilter={displayFilter}
          onApplyFilter={setDisplayFilter}
          matchingCount={filteredPackets.length}
          totalCount={packets.length}
        />
      </div>

      {/* Split Workstation: Table & Inspector */}
      <div className={`flex-1 flex gap-3 overflow-hidden ${splitMode === 'vertical' ? 'flex-col lg:flex-row' : 'flex-col'}`}>
        {/* Packets Table */}
        <div className={splitMode === 'vertical' ? 'flex-1 lg:w-3/5 h-full overflow-hidden' : 'h-1/2 overflow-hidden'}>
          <PacketTable
            packets={displayedPackets}
            selectedPacket={selectedPacket}
            onSelectPacket={onSelectPacket}
            onFilterByProtocol={setDisplayFilter}
          />
        </div>

        {/* Packet Inspector */}
        <div className={splitMode === 'vertical' ? 'flex-1 lg:w-2/5 h-full overflow-hidden' : 'h-1/2 overflow-hidden'}>
          <PacketInspector packet={selectedPacket} />
        </div>
      </div>
    </div>
  );
};
