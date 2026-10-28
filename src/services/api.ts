/**
 * NetScope — Client API & WebSocket Communication Service
 */

import { Packet, NetworkInterface, CaptureSession, CaptureStatistics } from '../types/packet';

export type WebSocketListener = (data: any) => void;

class NetScopeApiService {
  private ws: WebSocket | null = null;
  private listeners: Set<WebSocketListener> = new Set();
  private reconnectTimeout: any = null;

  initWebSocket(onMessage: WebSocketListener) {
    this.listeners.add(onMessage);

    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/packets`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[NetScope WS] Connected to backend');
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          for (const listener of this.listeners) {
            listener(data);
          }
        } catch (err) {
          console.error('[NetScope WS] Error parsing message:', err);
        }
      };

      this.ws.onclose = () => {
        console.log('[NetScope WS] Connection closed. Retrying in 2s...');
        this.ws = null;
        if (!this.reconnectTimeout) {
          this.reconnectTimeout = setTimeout(() => {
            this.reconnectTimeout = null;
            this.initWebSocket(onMessage);
          }, 2000);
        }
      };

      this.ws.onerror = (err) => {
        console.warn('[NetScope WS] WebSocket error:', err);
      };
    } catch (e) {
      console.warn('[NetScope WS] WebSocket creation failed:', e);
    }
  }

  removeWebSocketListener(listener: WebSocketListener) {
    this.listeners.delete(listener);
  }

  async getInterfaces(): Promise<NetworkInterface[]> {
    const res = await fetch('/api/interfaces');
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to fetch interfaces');
    return data.interfaces;
  }

  async getCaptureStatus(): Promise<{
    isCapturing: boolean;
    sessionId?: string;
    interfaceName: string;
    packetCount: number;
    totalBytes: number;
    startTime: number;
  }> {
    const res = await fetch('/api/capture/status');
    const data = await res.json();
    return data;
  }

  async startCapture(interfaceName: string, bpfFilter?: string): Promise<any> {
    const res = await fetch('/api/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interfaceName, bpfFilter }),
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to start capture');
    return data;
  }

  async stopCapture(): Promise<any> {
    const res = await fetch('/api/capture/stop', { method: 'POST' });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to stop capture');
    return data;
  }

  async clearPackets(): Promise<void> {
    await fetch('/api/capture/clear', { method: 'POST' });
  }

  async getPackets(offset = 0, limit = 100, sessionId?: string): Promise<{ total: number; packets: Packet[] }> {
    const query = new URLSearchParams({
      offset: String(offset),
      limit: String(limit),
      ...(sessionId ? { sessionId } : {}),
    });
    const res = await fetch(`/api/packets?${query.toString()}`);
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to fetch packets');
    return { total: data.total, packets: data.packets };
  }

  async getHistory(): Promise<CaptureSession[]> {
    const res = await fetch('/api/history');
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to fetch history');
    return data.sessions;
  }

  async getSessionDetail(id: string): Promise<CaptureSession & { packets: Packet[] }> {
    const res = await fetch(`/api/history/${id}`);
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to fetch session detail');
    return data.session;
  }

  async deleteSession(id: string): Promise<void> {
    const res = await fetch(`/api/history/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to delete session');
  }

  getExportCsvUrl(sessionId?: string): string {
    return `/api/export/csv${sessionId ? `?sessionId=${sessionId}` : ''}`;
  }

  getExportJsonUrl(sessionId?: string): string {
    return `/api/export/json${sessionId ? `?sessionId=${sessionId}` : ''}`;
  }
}

export const apiService = new NetScopeApiService();

/**
 * Calculate deep statistics from a packet array
 */
export function calculateStatistics(packets: Packet[]): CaptureStatistics {
  const stats: CaptureStatistics = {
    totalPackets: packets.length,
    totalBytes: 0,
    durationSeconds: 0,
    packetsPerSecond: 0,
    bytesPerSecond: 0,
    averagePacketSize: 0,
    protocolCounts: {
      TCP: 0,
      UDP: 0,
      ICMP: 0,
      ARP: 0,
      DNS: 0,
      HTTP: 0,
      HTTPS: 0,
      TLS: 0,
      OTHER: 0,
    },
    ipCounts: {
      sources: {},
      destinations: {},
      conversations: {},
    },
    portCounts: {},
    packetSizeDistribution: {
      '0-64': 0,
      '65-128': 0,
      '129-512': 0,
      '513-1024': 0,
      '1025-1518': 0,
      '1519+': 0,
    },
    directionCounts: {
      INCOMING: 0,
      OUTGOING: 0,
      LOCAL: 0,
      TRANSIT: 0,
    },
  };

  if (packets.length === 0) return stats;

  let firstTs = packets[0].timestamp;
  let lastTs = packets[0].timestamp;

  for (const pkt of packets) {
    stats.totalBytes += pkt.length;
    if (pkt.timestamp < firstTs) firstTs = pkt.timestamp;
    if (pkt.timestamp > lastTs) lastTs = pkt.timestamp;

    // Protocol count
    const proto = pkt.protocol;
    if (proto in stats.protocolCounts) {
      stats.protocolCounts[proto as keyof typeof stats.protocolCounts]++;
    } else {
      stats.protocolCounts.OTHER++;
    }

    // IP counts
    if (pkt.srcIp) {
      stats.ipCounts.sources[pkt.srcIp] = (stats.ipCounts.sources[pkt.srcIp] || 0) + 1;
    }
    if (pkt.dstIp) {
      stats.ipCounts.destinations[pkt.dstIp] = (stats.ipCounts.destinations[pkt.dstIp] || 0) + 1;
    }
    if (pkt.srcIp && pkt.dstIp) {
      const convKey = [pkt.srcIp, pkt.dstIp].sort().join(' ⇄ ');
      stats.ipCounts.conversations[convKey] = (stats.ipCounts.conversations[convKey] || 0) + 1;
    }

    // Ports
    if (pkt.srcPort) stats.portCounts[pkt.srcPort] = (stats.portCounts[pkt.srcPort] || 0) + 1;
    if (pkt.dstPort) stats.portCounts[pkt.dstPort] = (stats.portCounts[pkt.dstPort] || 0) + 1;

    // Size distribution
    const sz = pkt.length;
    if (sz <= 64) stats.packetSizeDistribution['0-64']++;
    else if (sz <= 128) stats.packetSizeDistribution['65-128']++;
    else if (sz <= 512) stats.packetSizeDistribution['129-512']++;
    else if (sz <= 1024) stats.packetSizeDistribution['513-1024']++;
    else if (sz <= 1518) stats.packetSizeDistribution['1025-1518']++;
    else stats.packetSizeDistribution['1519+']++;

    // Direction
    const dir = pkt.direction || (pkt.srcIp?.startsWith('192.168.') || pkt.srcIp?.startsWith('10.') || pkt.srcIp === '127.0.0.1' ? 'OUTGOING' : 'INCOMING');
    stats.directionCounts[dir as keyof typeof stats.directionCounts] = (stats.directionCounts[dir as keyof typeof stats.directionCounts] || 0) + 1;
  }

  const durationMs = Math.max(1000, lastTs - firstTs);
  stats.durationSeconds = durationMs / 1000;
  stats.packetsPerSecond = Number((stats.totalPackets / stats.durationSeconds).toFixed(2));
  stats.bytesPerSecond = Number((stats.totalBytes / stats.durationSeconds).toFixed(2));
  stats.averagePacketSize = Math.round(stats.totalBytes / stats.totalPackets);

  return stats;
}
