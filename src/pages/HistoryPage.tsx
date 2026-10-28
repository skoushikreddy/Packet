/**
 * NetScope — Capture History & Database Manager (Graphite Minimal Theme)
 * Inspect persistent SQLite sessions, reload previous captures, export and delete records.
 */

import React, { useState, useEffect } from 'react';
import { 
  History, 
  Trash2, 
  ExternalLink, 
  Download, 
  AlertTriangle, 
  RefreshCw,
  HardDrive
} from 'lucide-react';
import { CaptureSession, Packet } from '../types/packet';
import { apiService } from '../services/api';

interface HistoryPageProps {
  onLoadSession: (packets: Packet[], sessionName: string) => void;
}

export const HistoryPage: React.FC<HistoryPageProps> = ({ onLoadSession }) => {
  const [sessions, setSessions] = useState<CaptureSession[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [, setError] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getHistory();
      setSessions(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load capture history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleReload = async (session: CaptureSession) => {
    setActionLoading(true);
    try {
      const detail = await apiService.getSessionDetail(session.id);
      if (detail && detail.packets) {
        onLoadSession(detail.packets, session.name);
      }
    } catch (err: any) {
      alert(`Error loading session: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await apiService.deleteSession(id);
      setSessions(prev => prev.filter(s => s.id !== id));
      setDeleteConfirmId(null);
    } catch (err: any) {
      alert(`Error deleting session: ${err.message}`);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs">
        <div className="space-y-1">
          <h2 className="text-base font-bold text-[#F3F4F6] flex items-center space-x-2">
            <History className="w-5 h-5 text-[#94A3B8]" />
            <span>Capture Sessions & Database Storage</span>
          </h2>
          <p className="text-xs text-[#A1A8B3]">
            Persistent archive of network capture sessions stored locally in SQLite database.
          </p>
        </div>
        <button
          onClick={fetchHistory}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#202429] hover:bg-[#383E45] text-[#D1D5DB] transition-colors cursor-pointer border border-[#454B53]"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-[#94A3B8] ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh List</span>
        </button>
      </div>

      {/* Confirmation Dialog for Delete */}
      {deleteConfirmId && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-6 max-w-md w-full shadow-2xl text-[#D1D5DB] space-y-4">
            <div className="flex items-center space-x-3 text-[#F87171]">
              <AlertTriangle className="w-6 h-6 shrink-0" />
              <h3 className="text-sm font-bold text-[#F3F4F6]">Confirm Deletion</h3>
            </div>
            <p className="text-xs text-[#A1A8B3] leading-relaxed">
              Are you sure you want to delete session <strong className="font-mono text-[#60A5FA]">{deleteConfirmId}</strong> from SQLite storage? This action cannot be undone.
            </p>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#202429] hover:bg-[#383E45] text-[#D1D5DB] transition-colors cursor-pointer border border-[#454B53]"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirmId)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#F87171] hover:bg-[#EF4444] text-[#191C20] transition-colors cursor-pointer"
              >
                Delete Session
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sessions Table Card */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-[#202429] text-[#A1A8B3] uppercase text-[10px] font-semibold border-b border-[#454B53]">
              <tr>
                <th className="py-3 px-4">Session ID / Name</th>
                <th className="py-3 px-4">Interface</th>
                <th className="py-3 px-4">Captured Packets</th>
                <th className="py-3 px-4">Total Bytes</th>
                <th className="py-3 px-4">Date & Time</th>
                <th className="py-3 px-4">Filter</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#363B42] font-mono">
              {sessions.map((sess) => (
                <tr key={sess.id} className="hover:bg-[#383E45]/40 text-[#D1D5DB] transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex flex-col">
                      <span className="font-bold text-[#F3F4F6] font-sans">{sess.name}</span>
                      <span className="text-[10px] text-[#7F8996]">{sess.id}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-[#202429] text-[#D1D5DB] border border-[#454B53] text-[11px]">
                      {sess.interfaceName}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-bold text-[#60A5FA]">
                    {sess.packetCount.toLocaleString()} pkts
                  </td>
                  <td className="py-3 px-4 text-[#D1D5DB]">
                    {formatBytes(sess.totalBytes)}
                  </td>
                  <td className="py-3 px-4 text-[#A1A8B3] text-[11px] font-sans">
                    {new Date(sess.startTime).toLocaleString()}
                  </td>
                  <td className="py-3 px-4">
                    {sess.bpfFilter ? (
                      <code className="bg-[#202429] text-[#60A5FA] px-1.5 py-0.5 rounded border border-[#454B53] text-[10px]">
                        {sess.bpfFilter}
                      </code>
                    ) : (
                      <span className="text-[#7F8996] text-[10px]">None (All)</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end space-x-1.5">
                      <button
                        onClick={() => handleReload(sess)}
                        disabled={actionLoading}
                        className="p-1.5 rounded-lg bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#60A5FA] transition-colors cursor-pointer"
                        title="Load packets into explorer"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                      <a
                        href={apiService.getExportCsvUrl(sess.id)}
                        className="p-1.5 rounded-lg bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#D1D5DB] transition-colors"
                        title="Export CSV"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </a>
                      <button
                        onClick={() => setDeleteConfirmId(sess.id)}
                        className="p-1.5 rounded-lg bg-[#202429] hover:bg-[#383E45] border border-[#454B53] text-[#F87171] transition-colors cursor-pointer"
                        title="Delete Session"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}

              {sessions.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#7F8996] font-sans">
                    <HardDrive className="w-8 h-8 text-[#626B76] mx-auto mb-2 opacity-50" />
                    <span>No saved capture sessions found in database.</span>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
