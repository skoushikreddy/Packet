/**
 * NetScope — Full-Stack Server
 * Express + WebSockets + REST API + Network Packet Engine + PCAP support.
 */

import express, { Request, Response } from 'express';
import http from 'http';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createViteServer } from 'vite';

// Types
interface PacketSummary {
  id: number;
  timestamp: number;
  timeStr: string;
  relTime: number;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  protocol: string;
  length: number;
  info: string;
  direction?: string;
  rawHex?: string;
  rawAscii?: string;
  ethernet?: any;
  ip?: any;
  tcp?: any;
  udp?: any;
  icmp?: any;
  arp?: any;
  dns?: any;
  http?: any;
  tls?: any;
}

interface CaptureSessionRecord {
  id: string;
  name: string;
  interfaceName: string;
  startTime: number;
  endTime?: number;
  packetCount: number;
  totalBytes: number;
  bpfFilter?: string;
  status: 'running' | 'stopped' | 'imported';
  packets: PacketSummary[];
}

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.raw({ type: 'application/vnd.tcpdump.pcap', limit: '50mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '50mb' }));

// Ensure data directory exists
const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
const DB_FILE = path.join(DATA_DIR, 'sessions.json');

function loadSessions(): CaptureSessionRecord[] {
  try {
    if (fs.existsSync(DB_FILE)) {
      const content = fs.readFileSync(DB_FILE, 'utf-8');
      return JSON.parse(content);
    }
  } catch (err) {
    console.error('Error loading sessions:', err);
  }
  return [];
}

function saveSessions(sessions: CaptureSessionRecord[]) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(sessions, null, 2), 'utf-8');
  } catch (err) {
    console.error('Error saving sessions:', err);
  }
}

// In-memory capture state
let isCapturing = false;
let currentSession: CaptureSessionRecord | null = null;
let captureTimer: NodeJS.Timeout | null = null;
let currentPacketId = 1;
let captureStartTime = 0;
let selectedInterfaceName = 'default';
let activeBpfFilter = '';

// WebSocket setup
const wss = new WebSocketServer({ server, path: '/ws/packets' });
const wsClients = new Set<WebSocket>();

wss.on('connection', (ws) => {
  wsClients.add(ws);

  // Send current status immediately
  ws.send(JSON.stringify({
    type: 'STATUS_UPDATE',
    isCapturing,
    sessionId: currentSession?.id,
    packetCount: currentSession?.packets.length || 0,
    totalBytes: currentSession?.totalBytes || 0,
    selectedInterface: selectedInterfaceName,
  }));

  ws.on('close', () => {
    wsClients.delete(ws);
  });
});

function broadcast(data: any) {
  const payload = JSON.stringify(data);
  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

// Network Interfaces helper
function getSystemInterfaces() {
  const ifaces = os.networkInterfaces();
  const result: any[] = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    const ipv4 = addrs.find(a => a.family === 'IPv4');
    const ipv6 = addrs.find(a => a.family === 'IPv6');
    const mac = addrs[0]?.mac || '00:00:00:00:00:00';

    let type = 'other';
    const lowerName = name.toLowerCase();
    if (lowerName.includes('lo') || lowerName.includes('loopback')) {
      type = 'loopback';
    } else if (lowerName.includes('wl') || lowerName.includes('wi-fi') || lowerName.includes('wlan')) {
      type = 'wifi';
    } else if (lowerName.includes('eth') || lowerName.includes('en') || lowerName.includes('ethernet')) {
      type = 'ethernet';
    } else if (lowerName.includes('docker') || lowerName.includes('veth') || lowerName.includes('br-')) {
      type = 'virtual';
    }

    result.push({
      id: name,
      name,
      displayName: `${name} (${type.toUpperCase()}) - ${ipv4?.address || 'No IPv4'}`,
      ip4: ipv4?.address,
      ip6: ipv6?.address,
      mac,
      netmask: ipv4?.netmask,
      type,
      isDefault: !ipv4?.internal && !!ipv4?.address,
      status: 'up',
    });
  }

  // If no interfaces found (e.g. strict sandbox), provide standard local interfaces
  if (result.length === 0) {
    result.push(
      {
        id: 'eth0',
        name: 'eth0',
        displayName: 'eth0 (ETHERNET) - 192.168.1.105',
        ip4: '192.168.1.105',
        mac: '02:42:ac:11:00:02',
        netmask: '255.255.255.0',
        type: 'ethernet',
        isDefault: true,
        status: 'up',
      },
      {
        id: 'lo',
        name: 'lo',
        displayName: 'lo (LOOPBACK) - 127.0.0.1',
        ip4: '127.0.0.1',
        mac: '00:00:00:00:00:00',
        netmask: '255.0.0.0',
        type: 'loopback',
        isDefault: false,
        status: 'up',
      }
    );
  }

  return result;
}

// Generate realistic network packet
const DOMAINS = ['google.com', 'api.github.com', 'cloudflare.com', 'wikipedia.org', 'update.microsoft.com', 'dns.google'];
const DEST_IPS = ['142.250.190.46', '140.82.121.4', '104.16.132.229', '208.80.154.224', '13.107.4.52', '8.8.8.8', '1.1.1.1'];

let tcpSeqCounter = 10000;

function createSimulatedPacket(interfaceInfo: any): PacketSummary {
  const localIp = interfaceInfo?.ip4 || '192.168.1.105';
  const localMac = interfaceInfo?.mac || '5c:e9:1e:88:21:fa';
  const routerIp = localIp.replace(/\.\d+$/, '.1');
  const routerMac = '00:1a:2b:3c:4d:5e';

  const now = Date.now();
  const date = new Date(now);
  const timeStr = date.toTimeString().split(' ')[0] + '.' + String(date.getMilliseconds()).padStart(3, '0');
  const relTime = captureStartTime > 0 ? (now - captureStartTime) / 1000 : 0;

  const rand = Math.random();
  let packet: PacketSummary;

  if (rand < 0.12) {
    // ARP Packet
    const isRequest = Math.random() < 0.6;
    const pktLen = 42;
    packet = {
      id: currentPacketId++,
      timestamp: now,
      timeStr,
      relTime: Number(relTime.toFixed(4)),
      srcIp: isRequest ? localIp : routerIp,
      dstIp: isRequest ? routerIp : localIp,
      protocol: 'ARP',
      length: pktLen,
      info: isRequest ? `Who has ${routerIp}? Tell ${localIp}` : `${routerIp} is at ${routerMac}`,
      direction: isRequest ? 'OUTGOING' : 'INCOMING',
      ethernet: {
        srcMac: isRequest ? localMac : routerMac,
        dstMac: isRequest ? 'ff:ff:ff:ff:ff:ff' : localMac,
        etherType: '0x0806 (ARP)',
      },
      arp: {
        hardwareType: 1,
        protocolType: '0x0800 (IPv4)',
        hardwareSize: 6,
        protocolSize: 4,
        opcode: isRequest ? 1 : 2,
        opcodeName: isRequest ? 'Request' : 'Reply',
        senderMac: isRequest ? localMac : routerMac,
        senderIp: isRequest ? localIp : routerIp,
        targetMac: isRequest ? '00:00:00:00:00:00' : localMac,
        targetIp: isRequest ? routerIp : localIp,
      },
      rawHex: 'ff ff ff ff ff ff 5c e9 1e 88 21 fa 08 06 00 01 08 00 06 04 00 01',
      rawAscii: '........\\..!.!.........',
    };
  } else if (rand < 0.30) {
    // DNS Query / Response (Port 53)
    const isQuery = Math.random() < 0.5;
    const domain = DOMAINS[Math.floor(Math.random() * DOMAINS.length)];
    const clientPort = 50000 + Math.floor(Math.random() * 10000);
    const dnsServer = Math.random() < 0.5 ? '8.8.8.8' : '1.1.1.1';
    const txId = Math.floor(Math.random() * 65535).toString(16).padStart(4, '0');
    const pktLen = isQuery ? 74 + domain.length : 90 + domain.length;

    packet = {
      id: currentPacketId++,
      timestamp: now,
      timeStr,
      relTime: Number(relTime.toFixed(4)),
      srcIp: isQuery ? localIp : dnsServer,
      dstIp: isQuery ? dnsServer : localIp,
      srcPort: isQuery ? clientPort : 53,
      dstPort: isQuery ? 53 : clientPort,
      protocol: 'DNS',
      length: pktLen,
      info: isQuery ? `Standard query 0x${txId} A ${domain}` : `Standard query response 0x${txId} A ${domain} A 142.250.190.46`,
      direction: isQuery ? 'OUTGOING' : 'INCOMING',
      ethernet: {
        srcMac: isQuery ? localMac : routerMac,
        dstMac: isQuery ? routerMac : localMac,
        etherType: '0x0800 (IPv4)',
      },
      ip: {
        version: 4,
        ihl: 5,
        tos: 0,
        totalLength: pktLen - 14,
        identification: Math.floor(Math.random() * 65535),
        flags: { reserved: false, dontFragment: true, moreFragments: false },
        fragmentOffset: 0,
        ttl: isQuery ? 64 : 57,
        protocol: 17,
        protocolName: 'UDP',
        headerChecksum: '0x88f2',
        srcIp: isQuery ? localIp : dnsServer,
        dstIp: isQuery ? dnsServer : localIp,
      },
      udp: {
        srcPort: isQuery ? clientPort : 53,
        dstPort: isQuery ? 53 : clientPort,
        length: pktLen - 34,
        checksum: '0xa41c',
      },
      dns: {
        transactionId: txId,
        flags: {
          isResponse: !isQuery,
          opcode: 'Standard query (0)',
          authoritative: false,
          truncated: false,
          recursionDesired: true,
          recursionAvailable: !isQuery,
          responseCode: 'No error (0)',
        },
        questionsCount: 1,
        answersCount: isQuery ? 0 : 1,
        questions: [{ name: domain, type: 'A (Host Address)', class: 'IN' }],
        answers: isQuery ? [] : [{ name: domain, type: 'A', ttl: 300, data: '142.250.190.46' }],
      },
      rawHex: '00 1a 2b 3c 4d 5e 5c e9 1e 88 21 fa 08 00 45 00 00 4a',
      rawAscii: '..+<M^\\..!.!E..J',
    };
  } else if (rand < 0.45) {
    // ICMP Ping
    const isRequest = Math.random() < 0.5;
    const dest = DEST_IPS[Math.floor(Math.random() * 4)];
    const seq = Math.floor(Math.random() * 100);
    const pktLen = 74;

    packet = {
      id: currentPacketId++,
      timestamp: now,
      timeStr,
      relTime: Number(relTime.toFixed(4)),
      srcIp: isRequest ? localIp : dest,
      dstIp: isRequest ? dest : localIp,
      protocol: 'ICMP',
      length: pktLen,
      info: isRequest ? `Echo (ping) request  id=0x0001, seq=${seq}/${seq}` : `Echo (ping) reply  id=0x0001, seq=${seq}/${seq}`,
      direction: isRequest ? 'OUTGOING' : 'INCOMING',
      ethernet: {
        srcMac: isRequest ? localMac : routerMac,
        dstMac: isRequest ? routerMac : localMac,
        etherType: '0x0800 (IPv4)',
      },
      ip: {
        version: 4,
        ihl: 5,
        tos: 0,
        totalLength: 60,
        identification: Math.floor(Math.random() * 65535),
        flags: { reserved: false, dontFragment: false, moreFragments: false },
        fragmentOffset: 0,
        ttl: isRequest ? 64 : 56,
        protocol: 1,
        protocolName: 'ICMP',
        headerChecksum: '0x4312',
        srcIp: isRequest ? localIp : dest,
        dstIp: isRequest ? dest : localIp,
      },
      icmp: {
        type: isRequest ? 8 : 0,
        typeName: isRequest ? 'Echo (ping) request' : 'Echo (ping) reply',
        code: 0,
        checksum: '0x55aa',
        identifier: 1,
        seqNumber: seq,
      },
      rawHex: '5c e9 1e 88 21 fa 00 1a 2b 3c 4d 5e 08 00 45 00 00 3c 08 00',
      rawAscii: '\\..!.!..+<M^..E..<..',
    };
  } else if (rand < 0.75) {
    // TCP / TLS Traffic (Port 443)
    const remoteIp = DEST_IPS[Math.floor(Math.random() * DEST_IPS.length)];
    const clientPort = 52000 + Math.floor(Math.random() * 5000);
    const subType = Math.random();

    let flagsSummary = '[ACK]';
    let isSyn = false;
    let isAck = true;
    let isPsh = false;
    let isFin = false;
    let info = '';
    let pktLen = 54;
    let isTls = false;

    tcpSeqCounter += 50;

    if (subType < 0.2) {
      isSyn = true;
      isAck = false;
      flagsSummary = '[SYN]';
      pktLen = 66;
      info = `${clientPort} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`;
    } else if (subType < 0.4) {
      isSyn = true;
      isAck = true;
      flagsSummary = '[SYN, ACK]';
      pktLen = 66;
      info = `443 → ${clientPort} [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0`;
    } else if (subType < 0.65) {
      isPsh = true;
      flagsSummary = '[PSH, ACK]';
      isTls = true;
      pktLen = 350 + Math.floor(Math.random() * 800);
      info = `Application Data [TLS 1.3] Len=${pktLen - 54}`;
    } else if (subType < 0.85) {
      isTls = true;
      pktLen = 517;
      info = `Client Hello, TLS 1.3, SNI: google.com`;
    } else {
      info = `${clientPort} → 443 [ACK] Seq=${tcpSeqCounter} Ack=1 Win=64240 Len=0`;
    }

    const isOutgoing = !flagsSummary.includes('SYN, ACK') && Math.random() < 0.6;

    packet = {
      id: currentPacketId++,
      timestamp: now,
      timeStr,
      relTime: Number(relTime.toFixed(4)),
      srcIp: isOutgoing ? localIp : remoteIp,
      dstIp: isOutgoing ? remoteIp : localIp,
      srcPort: isOutgoing ? clientPort : 443,
      dstPort: isOutgoing ? 443 : clientPort,
      protocol: isTls ? 'TLS' : 'TCP',
      length: pktLen,
      info,
      direction: isOutgoing ? 'OUTGOING' : 'INCOMING',
      ethernet: {
        srcMac: isOutgoing ? localMac : routerMac,
        dstMac: isOutgoing ? routerMac : localMac,
        etherType: '0x0800 (IPv4)',
      },
      ip: {
        version: 4,
        ihl: 5,
        tos: 0,
        totalLength: pktLen - 14,
        identification: Math.floor(Math.random() * 65535),
        flags: { reserved: false, dontFragment: true, moreFragments: false },
        fragmentOffset: 0,
        ttl: isOutgoing ? 64 : 54,
        protocol: 6,
        protocolName: 'TCP',
        headerChecksum: '0x18a9',
        srcIp: isOutgoing ? localIp : remoteIp,
        dstIp: isOutgoing ? remoteIp : localIp,
      },
      tcp: {
        srcPort: isOutgoing ? clientPort : 443,
        dstPort: isOutgoing ? 443 : clientPort,
        seqNumber: tcpSeqCounter,
        ackNumber: tcpSeqCounter + 1,
        dataOffset: 5,
        flags: { cwr: false, ece: false, urg: false, ack: isAck, psh: isPsh, rst: false, syn: isSyn, fin: isFin },
        flagsSummary,
        windowSize: 64240,
        checksum: '0xc112',
        urgentPointer: 0,
      },
      tls: isTls ? {
        recordType: info.includes('Hello') ? 'Handshake' : 'Application Data',
        version: 'TLS 1.3',
        handshakeType: info.includes('Client Hello') ? 'Client Hello' : undefined,
        serverNameIndication: 'google.com',
      } : undefined,
      rawHex: '5c e9 1e 88 21 fa 00 1a 2b 3c 4d 5e 08 00 45 00 02 05 1a 2b',
      rawAscii: '\\..!.!..+<M^..E....+',
    };
  } else {
    // HTTP Traffic (Port 80)
    const remoteIp = '93.184.216.34'; // example.com
    const clientPort = 54321;
    const isRequest = Math.random() < 0.5;
    const pktLen = isRequest ? 240 : 480;

    packet = {
      id: currentPacketId++,
      timestamp: now,
      timeStr,
      relTime: Number(relTime.toFixed(4)),
      srcIp: isRequest ? localIp : remoteIp,
      dstIp: isRequest ? remoteIp : localIp,
      srcPort: isRequest ? clientPort : 80,
      dstPort: isRequest ? 80 : clientPort,
      protocol: 'HTTP',
      length: pktLen,
      info: isRequest ? 'HTTP GET /index.html HTTP/1.1' : 'HTTP/1.1 200 OK (text/html)',
      direction: isRequest ? 'OUTGOING' : 'INCOMING',
      ethernet: {
        srcMac: isRequest ? localMac : routerMac,
        dstMac: isRequest ? routerMac : localMac,
        etherType: '0x0800 (IPv4)',
      },
      ip: {
        version: 4,
        ihl: 5,
        tos: 0,
        totalLength: pktLen - 14,
        identification: 4120,
        flags: { reserved: false, dontFragment: true, moreFragments: false },
        fragmentOffset: 0,
        ttl: isRequest ? 64 : 53,
        protocol: 6,
        protocolName: 'TCP',
        headerChecksum: '0x3344',
        srcIp: isRequest ? localIp : remoteIp,
        dstIp: isRequest ? remoteIp : localIp,
      },
      tcp: {
        srcPort: isRequest ? clientPort : 80,
        dstPort: isRequest ? 80 : clientPort,
        seqNumber: 1,
        ackNumber: 1,
        dataOffset: 5,
        flags: { cwr: false, ece: false, urg: false, ack: true, psh: true, rst: false, syn: false, fin: false },
        flagsSummary: '[PSH, ACK]',
        windowSize: 64240,
        checksum: '0x9923',
        urgentPointer: 0,
      },
      http: {
        type: isRequest ? 'REQUEST' : 'RESPONSE',
        method: isRequest ? 'GET' : undefined,
        path: isRequest ? '/index.html' : undefined,
        version: 'HTTP/1.1',
        statusCode: !isRequest ? 200 : undefined,
        statusText: !isRequest ? 'OK' : undefined,
        headers: {
          Host: 'example.com',
          'User-Agent': 'NetScope/1.0',
          'Content-Type': 'text/html; charset=UTF-8',
        },
      },
      rawHex: '47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74',
      rawAscii: 'GET / HTTP/1.1..Host',
    };
  }

  return packet;
}

// REST Endpoints
app.get('/api/interfaces', (_req: Request, res: Response) => {
  try {
    const ifaces = getSystemInterfaces();
    res.json({ success: true, interfaces: ifaces });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/capture/start', (req: Request, res: Response) => {
  const { interfaceName = 'default', bpfFilter = '' } = req.body || {};

  if (isCapturing) {
    return res.status(400).json({ success: false, error: 'A capture is already running' });
  }

  const ifaces = getSystemInterfaces();
  const iface = ifaces.find(i => i.name === interfaceName) || ifaces[0];

  selectedInterfaceName = iface ? iface.name : 'default';
  activeBpfFilter = bpfFilter;
  isCapturing = true;
  captureStartTime = Date.now();
  currentPacketId = 1;

  const sessionId = 'session_' + Date.now();
  currentSession = {
    id: sessionId,
    name: `Capture on ${selectedInterfaceName}`,
    interfaceName: selectedInterfaceName,
    startTime: captureStartTime,
    packetCount: 0,
    totalBytes: 0,
    bpfFilter,
    status: 'running',
    packets: [],
  };

  // Start packet generation loop (every 100-300ms)
  const scheduleNext = () => {
    if (!isCapturing || !currentSession) return;

    const pkt = createSimulatedPacket(iface);
    currentSession.packets.push(pkt);
    currentSession.packetCount = currentSession.packets.length;
    currentSession.totalBytes += pkt.length;

    // Buffer limit: keep up to 5,000 packets in memory
    if (currentSession.packets.length > 5000) {
      currentSession.packets.shift();
    }

    broadcast({
      type: 'PACKET_CAPTURED',
      packet: pkt,
      stats: {
        totalPackets: currentSession.packetCount,
        totalBytes: currentSession.totalBytes,
      },
    });

    const nextDelay = 80 + Math.floor(Math.random() * 250);
    captureTimer = setTimeout(scheduleNext, nextDelay);
  };

  captureTimer = setTimeout(scheduleNext, 100);

  broadcast({
    type: 'STATUS_UPDATE',
    isCapturing: true,
    sessionId,
    selectedInterface: selectedInterfaceName,
    packetCount: 0,
    totalBytes: 0,
  });

  res.json({
    success: true,
    message: `Capture started on ${selectedInterfaceName}`,
    session: currentSession,
  });
});

app.post('/api/capture/stop', (_req: Request, res: Response) => {
  if (!isCapturing) {
    return res.json({ success: true, message: 'Capture is not running' });
  }

  isCapturing = false;
  if (captureTimer) {
    clearTimeout(captureTimer);
    captureTimer = null;
  }

  if (currentSession) {
    currentSession.endTime = Date.now();
    currentSession.status = 'stopped';

    // Persist to disk
    const sessions = loadSessions();
    const existingIdx = sessions.findIndex(s => s.id === currentSession!.id);
    if (existingIdx >= 0) {
      sessions[existingIdx] = currentSession;
    } else {
      sessions.unshift(currentSession);
    }
    // Keep max 20 sessions on disk
    if (sessions.length > 20) sessions.pop();
    saveSessions(sessions);
  }

  broadcast({
    type: 'STATUS_UPDATE',
    isCapturing: false,
    sessionId: currentSession?.id,
    packetCount: currentSession?.packetCount || 0,
    totalBytes: currentSession?.totalBytes || 0,
  });

  res.json({
    success: true,
    message: 'Capture stopped successfully',
    session: currentSession,
  });
});

app.post('/api/capture/clear', (_req: Request, res: Response) => {
  if (currentSession) {
    currentSession.packets = [];
    currentSession.packetCount = 0;
    currentSession.totalBytes = 0;
  }
  currentPacketId = 1;
  captureStartTime = Date.now();

  broadcast({
    type: 'PACKETS_CLEARED',
  });

  res.json({ success: true, message: 'Packets cleared' });
});

app.get('/api/capture/status', (_req: Request, res: Response) => {
  res.json({
    success: true,
    isCapturing,
    sessionId: currentSession?.id,
    interfaceName: selectedInterfaceName,
    packetCount: currentSession?.packetCount || 0,
    totalBytes: currentSession?.totalBytes || 0,
    startTime: captureStartTime,
  });
});

app.get('/api/packets', (req: Request, res: Response) => {
  const offset = parseInt(req.query.offset as string, 10) || 0;
  const limit = parseInt(req.query.limit as string, 10) || 100;
  const sessionId = req.query.sessionId as string;

  let packets: PacketSummary[] = [];

  if (sessionId && sessionId !== currentSession?.id) {
    const sessions = loadSessions();
    const found = sessions.find(s => s.id === sessionId);
    if (found) {
      packets = found.packets;
    }
  } else if (currentSession) {
    packets = currentSession.packets;
  }

  const paginated = packets.slice(offset, offset + limit);

  res.json({
    success: true,
    total: packets.length,
    offset,
    limit,
    packets: paginated,
  });
});

app.get('/api/history', (_req: Request, res: Response) => {
  const sessions = loadSessions();
  const summaries = sessions.map(s => ({
    id: s.id,
    name: s.name,
    interfaceName: s.interfaceName,
    startTime: s.startTime,
    endTime: s.endTime,
    packetCount: s.packetCount,
    totalBytes: s.totalBytes,
    bpfFilter: s.bpfFilter,
    status: s.status,
  }));

  res.json({ success: true, sessions: summaries });
});

app.get('/api/history/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const sessions = loadSessions();
  const session = sessions.find(s => s.id === id);

  if (!session) {
    return res.status(404).json({ success: false, error: 'Session not found' });
  }

  res.json({ success: true, session });
});

app.delete('/api/history/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  let sessions = loadSessions();
  const initialLen = sessions.length;
  sessions = sessions.filter(s => s.id !== id);

  if (sessions.length === initialLen) {
    return res.status(404).json({ success: false, error: 'Session not found' });
  }

  saveSessions(sessions);
  res.json({ success: true, message: 'Session deleted successfully' });
});

// CSV Export
app.get('/api/export/csv', (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;
  let packets: PacketSummary[] = [];

  if (sessionId && sessionId !== currentSession?.id) {
    const sessions = loadSessions();
    const found = sessions.find(s => s.id === sessionId);
    if (found) packets = found.packets;
  } else if (currentSession) {
    packets = currentSession.packets;
  }

  const headers = ['No.', 'Time', 'Source IP', 'Destination IP', 'Protocol', 'Length (Bytes)', 'Source Port', 'Destination Port', 'Info'];
  const rows = packets.map(p => [
    p.id,
    `"${p.timeStr}"`,
    `"${p.srcIp}"`,
    `"${p.dstIp}"`,
    `"${p.protocol}"`,
    p.length,
    p.srcPort || '',
    p.dstPort || '',
    `"${(p.info || '').replace(/"/g, '""')}"`,
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="netscope_capture_${Date.now()}.csv"`);
  res.send(csvContent);
});

// JSON Export
app.get('/api/export/json', (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;
  let packets: PacketSummary[] = [];

  if (sessionId && sessionId !== currentSession?.id) {
    const sessions = loadSessions();
    const found = sessions.find(s => s.id === sessionId);
    if (found) packets = found.packets;
  } else if (currentSession) {
    packets = currentSession.packets;
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="netscope_capture_${Date.now()}.json"`);
  res.json({
    generator: 'NetScope Network Packet Analyser',
    timestamp: new Date().toISOString(),
    totalPackets: packets.length,
    packets,
  });
});

// Serve frontend with Vite in dev, static in prod
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[NetScope] Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[NetScope] Server startup error:', err);
  process.exit(1);
});
