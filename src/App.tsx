/**
 * NetScope — Network Packet Analyser
 * Root Application Component (Graphite Minimal Theme)
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavigationTab } from './components/Sidebar';
import { ExportModal } from './components/ExportModal';

import { OverviewPage } from './pages/OverviewPage';
import { LiveCapturePage } from './pages/LiveCapturePage';
import { PacketExplorerPage } from './pages/PacketExplorerPage';
import { ProtocolAnalysisPage } from './pages/ProtocolAnalysisPage';
import { TrafficMonitorPage } from './pages/TrafficMonitorPage';
import { HistoryPage } from './pages/HistoryPage';
import { PcapImportPage } from './pages/PcapImportPage';
import { AcademicGuidePage } from './pages/AcademicGuidePage';
import { SettingsPage } from './pages/SettingsPage';
import { AboutPage } from './pages/AboutPage';

import { Packet, NetworkInterface, CaptureStatistics } from './types/packet';
import { apiService, calculateStatistics } from './services/api';
import { generateSamplePackets } from './utils/pcapParser';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('default');
  const [isCapturing, setIsCapturing] = useState<boolean>(false);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [bufferLimit, setBufferLimit] = useState<number>(5000);
  const [isConnected, setIsConnected] = useState<boolean>(true);
  const [isExportOpen, setIsExportOpen] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'info' | 'success' | 'warn' } | null>(null);

  const showToast = (text: string, type: 'info' | 'success' | 'warn' = 'info') => {
    setToastMessage({ text, type });
    setTimeout(() => setToastMessage(null), 3000);
  };

  // Compute live statistics
  const stats: CaptureStatistics = useMemo(() => {
    return calculateStatistics(packets);
  }, [packets]);

  // Load interfaces on mount
  useEffect(() => {
    const fetchInterfaces = async () => {
      try {
        const ifaces = await apiService.getInterfaces();
        setInterfaces(ifaces);
        const def = ifaces.find(i => i.isDefault) || ifaces[0];
        if (def) setSelectedInterface(def.name);
      } catch (err) {
        console.warn('Could not fetch network interfaces:', err);
      }
    };
    fetchInterfaces();
  }, []);

  // WebSocket message receiver
  const handleWsMessage = useCallback((data: any) => {
    if (data.type === 'PACKET_CAPTURED') {
      const newPkt: Packet = data.packet;
      setPackets((prev) => {
        const next = [...prev, newPkt];
        if (next.length > bufferLimit) {
          return next.slice(next.length - bufferLimit);
        }
        return next;
      });
    } else if (data.type === 'STATUS_UPDATE') {
      setIsCapturing(data.isCapturing);
      if (data.selectedInterface) {
        setSelectedInterface(data.selectedInterface);
      }
    } else if (data.type === 'PACKETS_CLEARED') {
      setPackets([]);
      setSelectedPacket(null);
    }
  }, [bufferLimit]);

  useEffect(() => {
    apiService.initWebSocket(handleWsMessage);
    return () => {
      apiService.removeWebSocketListener(handleWsMessage);
    };
  }, [handleWsMessage]);

  // Capture controls
  const handleStartCapture = async () => {
    try {
      await apiService.startCapture(selectedInterface);
      setIsCapturing(true);
      showToast(`Capture started on interface ${selectedInterface}`, 'success');
    } catch (err: any) {
      showToast(err.message || 'Failed to start capture', 'warn');
    }
  };

  const handleStopCapture = async () => {
    try {
      await apiService.stopCapture();
      setIsCapturing(false);
      showToast('Capture stopped and session saved to SQLite history', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to stop capture', 'warn');
    }
  };

  const handleClearPackets = async () => {
    try {
      await apiService.clearPackets();
      setPackets([]);
      setSelectedPacket(null);
      showToast('Packet buffer cleared', 'info');
    } catch (err) {
      setPackets([]);
      setSelectedPacket(null);
    }
  };

  const handleSaveCapture = async () => {
    if (isCapturing) {
      await handleStopCapture();
    } else {
      showToast('Current session is already saved in history', 'success');
    }
  };

  // Load sample academic trace
  const handleLoadSampleTrace = () => {
    const samples = generateSamplePackets();
    setPackets(samples);
    setSelectedPacket(samples[0]);
    showToast(`Loaded ${samples.length} reference packets (DNS, TCP 3-Way Handshake, ICMP, HTTP, TLS)`, 'success');
  };

  const handleLoadSessionFromHistory = (loadedPackets: Packet[], sessionTitle: string) => {
    setPackets(loadedPackets);
    if (loadedPackets.length > 0) setSelectedPacket(loadedPackets[0]);
    setActiveTab('explorer');
    showToast(`Loaded ${loadedPackets.length} packets from "${sessionTitle}"`, 'success');
  };

  return (
    <div className="min-h-screen bg-[#202327] text-[#D1D5DB] flex flex-col font-sans selection:bg-[#60A5FA]/30 selection:text-[#F3F4F6]">
      {/* Top Navbar */}
      <Navbar
        interfaces={interfaces}
        selectedInterface={selectedInterface}
        onSelectInterface={setSelectedInterface}
        isCapturing={isCapturing}
        onStartCapture={handleStartCapture}
        onStopCapture={handleStopCapture}
        onClearPackets={handleClearPackets}
        packetCount={packets.length}
        totalBytes={stats.totalBytes}
        packetsPerSec={stats.packetsPerSecond}
        isConnected={isConnected}
        onOpenExport={() => setIsExportOpen(true)}
        onLoadSampleTrace={handleLoadSampleTrace}
      />

      {/* Main Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          packetCount={packets.length}
          isCapturing={isCapturing}
        />

        {/* Center Main View Area */}
        <main className="flex-1 overflow-y-auto p-5 custom-scrollbar bg-[#202327]">
          {activeTab === 'overview' && (
            <OverviewPage
              packets={packets}
              stats={stats}
              isCapturing={isCapturing}
              onStartCapture={handleStartCapture}
              onStopCapture={handleStopCapture}
              selectedPacket={selectedPacket}
              onSelectPacket={setSelectedPacket}
              onNavigateToTab={setActiveTab}
              onLoadSampleTrace={handleLoadSampleTrace}
            />
          )}

          {activeTab === 'live-capture' && (
            <LiveCapturePage
              packets={packets}
              isCapturing={isCapturing}
              onStartCapture={handleStartCapture}
              onStopCapture={handleStopCapture}
              onClearPackets={handleClearPackets}
              onSaveCapture={handleSaveCapture}
              selectedPacket={selectedPacket}
              onSelectPacket={setSelectedPacket}
              selectedInterface={selectedInterface}
            />
          )}

          {activeTab === 'explorer' && (
            <PacketExplorerPage
              packets={packets}
              selectedPacket={selectedPacket}
              onSelectPacket={setSelectedPacket}
            />
          )}

          {activeTab === 'protocol-analysis' && (
            <ProtocolAnalysisPage
              packets={packets}
              stats={stats}
            />
          )}

          {activeTab === 'traffic-monitor' && (
            <TrafficMonitorPage
              packets={packets}
              stats={stats}
              isCapturing={isCapturing}
            />
          )}

          {activeTab === 'history' && (
            <HistoryPage
              onLoadSession={handleLoadSessionFromHistory}
            />
          )}

          {activeTab === 'pcap-import' && (
            <PcapImportPage
              onLoadPackets={handleLoadSessionFromHistory}
            />
          )}

          {activeTab === 'academic-guide' && (
            <AcademicGuidePage />
          )}

          {activeTab === 'settings' && (
            <SettingsPage
              interfaces={interfaces}
              selectedInterface={selectedInterface}
              onSelectInterface={setSelectedInterface}
              bufferLimit={bufferLimit}
              onSetBufferLimit={setBufferLimit}
            />
          )}

          {activeTab === 'about' && (
            <AboutPage />
          )}
        </main>
      </div>

      {/* Export Modal */}
      <ExportModal
        isOpen={isExportOpen}
        onClose={() => setIsExportOpen(false)}
        packets={packets}
        stats={stats}
        interfaceName={selectedInterface}
      />

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 animate-bounce">
          <div className={`px-4 py-2.5 rounded-xl text-xs font-semibold shadow-2xl flex items-center space-x-2 border ${
            toastMessage.type === 'success' 
              ? 'bg-[#292E34] border-[#34D399]/40 text-[#34D399]' 
              : toastMessage.type === 'warn'
              ? 'bg-[#292E34] border-[#FBBF24]/40 text-[#FBBF24]'
              : 'bg-[#292E34] border-[#60A5FA]/40 text-[#60A5FA]'
          }`}>
            <span>{toastMessage.text}</span>
          </div>
        </div>
      )}
    </div>
  );
}
