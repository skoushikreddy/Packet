/**
 * NetScope — Settings & Driver Configuration (Graphite Minimal Theme)
 * Interface selector, memory buffer limit, Npcap driver setup for Windows, and Linux capabilities.
 */

import React, { useState } from 'react';
import { 
  Settings, 
  Wifi, 
  ShieldCheck, 
  Terminal, 
  Sliders
} from 'lucide-react';
import { NetworkInterface } from '../types/packet';

interface SettingsPageProps {
  interfaces: NetworkInterface[];
  selectedInterface: string;
  onSelectInterface: (name: string) => void;
  bufferLimit: number;
  onSetBufferLimit: (limit: number) => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  interfaces,
  selectedInterface,
  onSelectInterface,
  bufferLimit,
  onSetBufferLimit,
}) => {
  const [activeOs, setActiveOs] = useState<'windows' | 'linux'>('windows');

  return (
    <div className="space-y-6 pb-12 max-w-4xl mx-auto text-[#D1D5DB] text-xs">
      {/* Page Header */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs">
        <div className="space-y-1">
          <h2 className="text-base font-bold text-[#F3F4F6] flex items-center space-x-2">
            <Settings className="w-5 h-5 text-[#94A3B8]" />
            <span>Settings & Operating System Driver Setup</span>
          </h2>
          <p className="text-xs text-[#A1A8B3]">
            Interface bindings, packet buffer sizes, Npcap drivers for Windows, and permissions.
          </p>
        </div>
      </div>

      {/* Network Interface Configuration */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-4">
        <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
          <Wifi className="w-4 h-4 text-[#60A5FA]" />
          <span>Active Network Interface</span>
        </h3>

        <div className="space-y-3">
          <label className="text-[#A1A8B3] text-xs block">
            Select the network adapter to monitor:
          </label>
          <select
            value={selectedInterface}
            onChange={(e) => onSelectInterface(e.target.value)}
            className="w-full bg-[#202429] border border-[#454B53] rounded-xl p-3 text-xs text-[#F3F4F6] outline-none focus:border-[#60A5FA] font-mono cursor-pointer"
          >
            {interfaces.map((iface) => (
              <option key={iface.id} value={iface.name} className="bg-[#24282D] text-[#D1D5DB]">
                {iface.name} ({iface.type.toUpperCase()}) — IP: {iface.ip4 || 'None'} • MAC: {iface.mac}
              </option>
            ))}
          </select>

          {/* Interface Details */}
          {interfaces.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#202429] p-4 rounded-xl border border-[#454B53] text-[11px] font-mono">
              <div>
                <span className="text-[#7F8996] block text-[10px] font-sans">NAME</span>
                <span className="text-[#60A5FA] font-bold">{selectedInterface}</span>
              </div>
              <div>
                <span className="text-[#7F8996] block text-[10px] font-sans">STATUS</span>
                <span className="text-[#34D399] font-bold">UP (Active)</span>
              </div>
              <div>
                <span className="text-[#7F8996] block text-[10px] font-sans">IP ADDRESS</span>
                <span className="text-[#F3F4F6] font-bold">{interfaces.find(i => i.name === selectedInterface)?.ip4 || '192.168.1.105'}</span>
              </div>
              <div>
                <span className="text-[#7F8996] block text-[10px] font-sans">MAC ADDRESS</span>
                <span className="text-[#D1D5DB]">{interfaces.find(i => i.name === selectedInterface)?.mac || '5c:e9:1e:88:21:fa'}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Buffer Memory Limit */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-4">
        <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
          <Sliders className="w-4 h-4 text-[#94A3B8]" />
          <span>In-Memory Packet Buffer Limit</span>
        </h3>

        <div className="space-y-3">
          <div className="flex justify-between text-xs">
            <span className="text-[#A1A8B3]">Maximum packets held in live browser RAM:</span>
            <span className="font-mono font-bold text-[#60A5FA]">{bufferLimit.toLocaleString()} packets</span>
          </div>

          <input
            type="range"
            min={500}
            max={10000}
            step={500}
            value={bufferLimit}
            onChange={(e) => onSetBufferLimit(Number(e.target.value))}
            className="w-full accent-[#60A5FA] cursor-pointer"
          />

          <p className="text-[11px] text-[#7F8996]">
            When the buffer limit is reached, older packets are shifted to conserve browser memory while all sessions are safely stored to the SQLite database.
          </p>
        </div>
      </div>

      {/* OS Compatibility & Setup Instructions (Windows / Linux) */}
      <div className="bg-[#292E34] border border-[#454B53] rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#F3F4F6] flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-[#94A3B8]" />
            <span>Driver Installation & Permissions Guide</span>
          </h3>

          <div className="flex bg-[#202429] p-1 rounded-lg border border-[#454B53] text-xs">
            <button
              onClick={() => setActiveOs('windows')}
              className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                activeOs === 'windows' ? 'bg-[#30353B] text-[#F3F4F6] font-semibold border border-[#454B53]' : 'text-[#A1A8B3] hover:text-[#F3F4F6]'
              }`}
            >
              Windows (Npcap)
            </button>
            <button
              onClick={() => setActiveOs('linux')}
              className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                activeOs === 'linux' ? 'bg-[#30353B] text-[#F3F4F6] font-semibold border border-[#454B53]' : 'text-[#A1A8B3] hover:text-[#F3F4F6]'
              }`}
            >
              Linux (Raw Sockets)
            </button>
          </div>
        </div>

        {activeOs === 'windows' ? (
          <div className="space-y-3 font-sans text-xs text-[#D1D5DB] leading-relaxed bg-[#202429] p-4 rounded-xl border border-[#454B53]">
            <h4 className="font-bold text-[#60A5FA]">Windows Installation & Npcap Configuration:</h4>
            <ol className="list-decimal list-inside space-y-2 text-[#A1A8B3]">
              <li>
                <strong className="text-[#F3F4F6]">Install Npcap:</strong> Download and run the Npcap installer from <code className="text-[#60A5FA] font-mono bg-[#191C20] px-1 py-0.5 rounded border border-[#363B42]">https://npcap.com/</code>.
              </li>
              <li>
                <strong className="text-[#F3F4F6]">Installation Options:</strong> During setup, ensure you check:
                <ul className="list-disc list-inside ml-5 mt-1 text-[#7F8996] text-[11px]">
                  <li>"Support raw 802.11 traffic (and monitor mode)"</li>
                  <li>"Install Npcap in WinPcap API-compatible Mode" (Crucial for Scapy)</li>
                </ul>
              </li>
              <li>
                <strong className="text-[#F3F4F6]">Run Terminal as Administrator:</strong> Windows requires Administrator privileges to open raw network sockets. Launch PowerShell or Command Prompt as Administrator.
              </li>
              <li>
                <strong className="text-[#F3F4F6]">Start Python Backend:</strong>
                <pre className="mt-1 p-3 bg-[#191C20] rounded-lg font-mono text-[11px] text-[#38BDF8] border border-[#363B42]">
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
                </pre>
              </li>
            </ol>
          </div>
        ) : (
          <div className="space-y-3 font-sans text-xs text-[#D1D5DB] leading-relaxed bg-[#202429] p-4 rounded-xl border border-[#454B53]">
            <h4 className="font-bold text-[#60A5FA]">Linux Raw Socket Capabilities:</h4>
            <ol className="list-decimal list-inside space-y-2 text-[#A1A8B3]">
              <li>
                <strong className="text-[#F3F4F6]">Install libpcap:</strong>
                <pre className="mt-1 p-3 bg-[#191C20] rounded-lg font-mono text-[11px] text-[#38BDF8] border border-[#363B42]">
sudo apt update && sudo apt install -y python3-pip python3-venv libpcap-dev
                </pre>
              </li>
              <li>
                <strong className="text-[#F3F4F6]">Grant Non-Root Raw Packet Capabilities (Recommended):</strong>
                <pre className="mt-1 p-3 bg-[#191C20] rounded-lg font-mono text-[11px] text-[#38BDF8] border border-[#363B42]">
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
                </pre>
              </li>
              <li>
                <strong className="text-[#F3F4F6]">Or Run with sudo:</strong> <code className="text-[#60A5FA] font-mono bg-[#191C20] px-1 py-0.5 rounded border border-[#363B42]">sudo python3 app.py</code>
              </li>
            </ol>
          </div>
        )}
      </div>

      {/* Ethical Safeguards Banner */}
      <div className="p-4 rounded-xl bg-[#292E34] border border-[#454B53] text-xs text-[#A1A8B3] flex items-start space-x-3 shadow-xs">
        <ShieldCheck className="w-5 h-5 text-[#34D399] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="font-bold text-[#F3F4F6]">Ethical Diagnostic & Academic Use Notice</h4>
          <p className="leading-relaxed text-[#7F8996]">
            NetScope is engineered exclusively for educational and network diagnostic analysis on authorized networks. It does not perform payload credential scraping, stealth surveillance, or unauthorized TLS decryption.
          </p>
        </div>
      </div>
    </div>
  );
};
