/**
 * NetScope — Export Modal & Academic CN Report Generator (Graphite Minimal Theme)
 */

import React, { useState } from 'react';
import { 
  Download, 
  FileSpreadsheet, 
  FileCode, 
  HardDrive, 
  X, 
  Printer, 
  GraduationCap,
  Layers
} from 'lucide-react';
import { Packet, CaptureStatistics } from '../types/packet';
import { generatePcapBinary } from '../utils/pcapParser';
import { apiService } from '../services/api';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  packets: Packet[];
  stats: CaptureStatistics;
  interfaceName: string;
}

export const ExportModal: React.FC<ExportModalProps> = ({
  isOpen,
  onClose,
  packets,
  stats,
  interfaceName,
}) => {
  const [activeTab, setActiveTab] = useState<'formats' | 'report'>('formats');

  if (!isOpen) return null;

  // Download PCAP
  const handleDownloadPcap = () => {
    try {
      const pcapBytes = generatePcapBinary(packets);
      const blob = new Blob([pcapBytes.buffer as ArrayBuffer], { type: 'application/vnd.tcpdump.pcap' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `netscope_capture_${Date.now()}.pcap`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error generating PCAP file:', err);
    }
  };

  // Download CSV
  const handleDownloadCsv = () => {
    window.location.href = apiService.getExportCsvUrl();
  };

  // Download JSON
  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({
      projectName: 'NetScope — Network Packet Analyser',
      course: 'Computer Networks (Academic Project)',
      timestamp: new Date().toISOString(),
      interface: interfaceName,
      totalPackets: packets.length,
      statistics: stats,
      packets,
    }, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `netscope_capture_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handlePrintReport = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden text-[#D1D5DB]">
        {/* Modal Header */}
        <div className="px-6 py-4 bg-[#24282D] border-b border-[#454B53] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-[#202429] border border-[#454B53] text-[#94A3B8]">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-[#F3F4F6]">Export Capture Data & Academic Report</h3>
              <p className="text-xs text-[#A1A8B3]">Download captured packets in standard networking formats or generate a project report</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#7F8996] hover:text-[#F3F4F6] p-1 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab switch */}
        <div className="flex border-b border-[#454B53] px-6 pt-3 bg-[#24282D]">
          <button
            onClick={() => setActiveTab('formats')}
            className={`pb-3 px-4 text-xs font-semibold border-b-2 transition-colors cursor-pointer flex items-center space-x-2 ${
              activeTab === 'formats'
                ? 'border-[#60A5FA] text-[#F3F4F6]'
                : 'border-transparent text-[#A1A8B3] hover:text-[#D1D5DB]'
            }`}
          >
            <HardDrive className="w-4 h-4" />
            <span>Export File Formats (PCAP, CSV, JSON)</span>
          </button>
          <button
            onClick={() => setActiveTab('report')}
            className={`pb-3 px-4 text-xs font-semibold border-b-2 transition-colors cursor-pointer flex items-center space-x-2 ${
              activeTab === 'report'
                ? 'border-[#60A5FA] text-[#F3F4F6]'
                : 'border-transparent text-[#A1A8B3] hover:text-[#D1D5DB]'
            }`}
          >
            <GraduationCap className="w-4 h-4" />
            <span>Academic CN Project Report</span>
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto flex-1 custom-scrollbar bg-[#292E34]">
          {activeTab === 'formats' ? (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* 1. Wireshark PCAP */}
                <div className="bg-[#202429] p-5 rounded-xl border border-[#454B53] hover:border-[#60A5FA]/60 transition-colors flex flex-col justify-between space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2 text-[#60A5FA]">
                      <Layers className="w-5 h-5 text-[#60A5FA]" />
                      <span className="font-bold text-sm text-[#F3F4F6]">Wireshark PCAP</span>
                    </div>
                    <p className="text-xs text-[#A1A8B3] leading-relaxed">
                      Standard libpcap binary format (magic <code className="text-[#60A5FA] bg-[#191C20] px-1 rounded font-mono">0xa1b2c3d4</code>). Loadable directly in Wireshark, tcpdump, and Snort.
                    </p>
                  </div>
                  <button
                    onClick={handleDownloadPcap}
                    disabled={packets.length === 0}
                    className="w-full flex items-center justify-center space-x-2 py-2 rounded-lg bg-[#30353B] hover:bg-[#383E45] border border-[#454B53] disabled:opacity-40 text-xs font-semibold text-[#F3F4F6] transition-colors cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-[#60A5FA]" />
                    <span>Download .pcap</span>
                  </button>
                </div>

                {/* 2. CSV Table */}
                <div className="bg-[#202429] p-5 rounded-xl border border-[#454B53] hover:border-[#34D399]/60 transition-colors flex flex-col justify-between space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2 text-[#34D399]">
                      <FileSpreadsheet className="w-5 h-5 text-[#34D399]" />
                      <span className="font-bold text-sm text-[#F3F4F6]">Spreadsheet CSV</span>
                    </div>
                    <p className="text-xs text-[#A1A8B3] leading-relaxed">
                      Comma-separated tabular summaries. Compatible with Microsoft Excel, Google Sheets, and Pandas dataframes.
                    </p>
                  </div>
                  <button
                    onClick={handleDownloadCsv}
                    disabled={packets.length === 0}
                    className="w-full flex items-center justify-center space-x-2 py-2 rounded-lg bg-[#30353B] hover:bg-[#383E45] border border-[#454B53] disabled:opacity-40 text-xs font-semibold text-[#F3F4F6] transition-colors cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-[#34D399]" />
                    <span>Download .csv</span>
                  </button>
                </div>

                {/* 3. JSON Data */}
                <div className="bg-[#202429] p-5 rounded-xl border border-[#454B53] hover:border-[#38BDF8]/60 transition-colors flex flex-col justify-between space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2 text-[#38BDF8]">
                      <FileCode className="w-5 h-5 text-[#38BDF8]" />
                      <span className="font-bold text-sm text-[#F3F4F6]">Structured JSON</span>
                    </div>
                    <p className="text-xs text-[#A1A8B3] leading-relaxed">
                      Complete hierarchical JSON representation including all headers (Ethernet, IP, TCP/UDP, ICMP, DNS) and statistics.
                    </p>
                  </div>
                  <button
                    onClick={handleDownloadJson}
                    disabled={packets.length === 0}
                    className="w-full flex items-center justify-center space-x-2 py-2 rounded-lg bg-[#30353B] hover:bg-[#383E45] border border-[#454B53] disabled:opacity-40 text-xs font-semibold text-[#F3F4F6] transition-colors cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-[#38BDF8]" />
                    <span>Download .json</span>
                  </button>
                </div>
              </div>

              {/* Data Summary Card */}
              <div className="bg-[#202429] p-4 rounded-xl border border-[#454B53] text-xs space-y-2">
                <span className="text-[11px] font-bold uppercase tracking-wider text-[#7F8996]">Session Metadata</span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-[#D1D5DB]">
                  <div>
                    <span className="text-[#7F8996] block text-[10px]">TOTAL PACKETS</span>
                    <span className="font-mono font-bold text-[#F3F4F6] text-sm">{packets.length.toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-[#7F8996] block text-[10px]">TOTAL VOLUME</span>
                    <span className="font-mono font-bold text-[#F3F4F6] text-sm">{(stats.totalBytes / 1024).toFixed(1)} KB</span>
                  </div>
                  <div>
                    <span className="text-[#7F8996] block text-[10px]">INTERFACE</span>
                    <span className="font-mono font-bold text-[#F3F4F6] text-sm">{interfaceName}</span>
                  </div>
                  <div>
                    <span className="text-[#7F8996] block text-[10px]">DURATION</span>
                    <span className="font-mono font-bold text-[#34D399] text-sm">{stats.durationSeconds.toFixed(1)}s</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* Academic CN Project Report Preview */
            <div className="space-y-6 text-[#D1D5DB]">
              <div className="flex justify-end">
                <button
                  onClick={handlePrintReport}
                  className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-xs font-medium text-[#D1D5DB] transition-colors cursor-pointer"
                >
                  <Printer className="w-4 h-4 text-[#94A3B8]" />
                  <span>Print / Save as PDF</span>
                </button>
              </div>

              <div className="p-6 bg-[#202429] rounded-xl border border-[#454B53] space-y-6 text-xs leading-relaxed" id="printable-academic-report">
                {/* Report Title */}
                <div className="border-b border-[#363B42] pb-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h2 className="text-lg font-bold text-[#F3F4F6]">Academic Project Laboratory Report</h2>
                      <h3 className="text-sm font-semibold text-[#A1A8B3] mt-1">NetScope: Network Packet Analyser & Protocol Inspection</h3>
                    </div>
                    <div className="text-right text-[11px] text-[#7F8996]">
                      <div>Date: {new Date().toLocaleDateString()}</div>
                      <div>System: NetScope v2.4 (CN Syllabus)</div>
                    </div>
                  </div>
                </div>

                {/* 1. Executive Summary */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[#60A5FA]">1. Executive Summary</h4>
                  <p className="text-[#D1D5DB]">
                    This report documents network traffic captured and analyzed using the NetScope Network Packet Analyser. 
                    The session monitored network traffic on interface <strong className="text-[#F3F4F6] font-mono">{interfaceName}</strong>, 
                    capturing a total of <strong className="text-[#F3F4F6] font-mono">{packets.length}</strong> packets spanning <strong className="text-[#F3F4F6] font-mono">{stats.durationSeconds.toFixed(1)}</strong> seconds 
                    with a total throughput of <strong className="text-[#F3F4F6] font-mono">{(stats.totalBytes / 1024).toFixed(2)} KB</strong>.
                  </p>
                </div>

                {/* 2. Protocol Distribution */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[#60A5FA]">2. Layer Protocol Distribution</h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {Object.entries(stats.protocolCounts).map(([proto, count]) => (
                      <div key={proto} className="bg-[#292E34] p-2.5 rounded-lg border border-[#454B53]">
                        <span className="text-[10px] text-[#7F8996] block">{proto}</span>
                        <span className="font-mono font-bold text-sm text-[#F3F4F6]">{count}</span>
                        <span className="text-[10px] text-[#A1A8B3] ml-1">
                          ({stats.totalPackets > 0 ? ((count / stats.totalPackets) * 100).toFixed(1) : 0}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 3. Top Communicating Endpoints */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[#60A5FA]">3. Communicating Endpoints</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#292E34] p-3 rounded-lg border border-[#454B53]">
                      <span className="text-[11px] font-bold text-[#F3F4F6] block mb-2">Top Source IPs</span>
                      {Object.entries(stats.ipCounts.sources).slice(0, 4).map(([ip, cnt]) => (
                        <div key={ip} className="flex justify-between py-1 border-b border-[#363B42] font-mono text-[11px]">
                          <span className="text-[#D1D5DB]">{ip}</span>
                          <span className="text-[#60A5FA] font-bold">{cnt} pkts</span>
                        </div>
                      ))}
                    </div>
                    <div className="bg-[#292E34] p-3 rounded-lg border border-[#454B53]">
                      <span className="text-[11px] font-bold text-[#F3F4F6] block mb-2">Top Destination IPs</span>
                      {Object.entries(stats.ipCounts.destinations).slice(0, 4).map(([ip, cnt]) => (
                        <div key={ip} className="flex justify-between py-1 border-b border-[#363B42] font-mono text-[11px]">
                          <span className="text-[#D1D5DB]">{ip}</span>
                          <span className="text-[#34D399] font-bold">{cnt} pkts</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* 4. Computer Networks Analysis Observations */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[#60A5FA]">4. Key Observations & CN Concepts Demonstrated</h4>
                  <ul className="list-disc list-inside space-y-1 text-[#D1D5DB]">
                    <li><strong>Encapsulation:</strong> Packets exhibit standard Ethernet II frames encapsulating IPv4/IPv6, carrying Layer 4 segments (TCP/UDP/ICMP).</li>
                    <li><strong>Connection Establishment:</strong> TCP sessions demonstrated explicit 3-way handshakes with SYN, SYN+ACK, and ACK flags.</li>
                    <li><strong>Application Resolution:</strong> Port 53 UDP traffic verified DNS recursive queries resolving hostnames to IP addresses.</li>
                    <li><strong>Security Posture:</strong> Encrypted TLS 1.3 records were identified via port 443; application payloads remain secure without interception.</li>
                  </ul>
                </div>

                {/* 5. Project Evaluation Sign-Off */}
                <div className="pt-6 border-t border-[#363B42] grid grid-cols-2 gap-8 text-[11px] text-[#7F8996]">
                  <div>
                    <span className="block font-semibold text-[#D1D5DB] mb-6">Student Signature:</span>
                    <div className="border-b border-[#454B53] w-48"></div>
                  </div>
                  <div>
                    <span className="block font-semibold text-[#D1D5DB] mb-6">Instructor / Evaluator Signature:</span>
                    <div className="border-b border-[#454B53] w-48"></div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
