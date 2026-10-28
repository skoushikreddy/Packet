/**
 * NetScope — Network Packet Analyser
 * Core TypeScript definitions for packets, protocol headers, statistics, and capture sessions.
 */

export type ProtocolType = 
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'ARP'
  | 'DNS'
  | 'HTTP'
  | 'HTTPS'
  | 'TLS'
  | 'IPv4'
  | 'IPv6'
  | 'OTHER';

export interface EthernetHeader {
  srcMac: string;
  dstMac: string;
  etherType: string; // e.g. "0x0800 (IPv4)", "0x0806 (ARP)"
}

export interface IPv4Header {
  version: number;
  ihl: number; // Internet Header Length in 32-bit words
  tos: number; // Type of service / DSCP
  totalLength: number;
  identification: number;
  flags: {
    reserved: boolean;
    dontFragment: boolean;
    moreFragments: boolean;
  };
  fragmentOffset: number;
  ttl: number; // Time to live
  protocol: number; // 6 = TCP, 17 = UDP, 1 = ICMP
  protocolName: string;
  headerChecksum: string;
  srcIp: string;
  dstIp: string;
}

export interface IPv6Header {
  version: number;
  trafficClass: number;
  flowLabel: number;
  payloadLength: number;
  nextHeader: number;
  nextHeaderName: string;
  hopLimit: number;
  srcIp: string;
  dstIp: string;
}

export interface TCPHeader {
  srcPort: number;
  dstPort: number;
  seqNumber: number;
  ackNumber: number;
  dataOffset: number; // Header length
  flags: {
    cwr: boolean;
    ece: boolean;
    urg: boolean;
    ack: boolean;
    psh: boolean;
    rst: boolean;
    syn: boolean;
    fin: boolean;
  };
  flagsSummary: string; // e.g. "[SYN, ACK]"
  windowSize: number;
  checksum: string;
  urgentPointer: number;
  options?: string;
}

export interface UDPHeader {
  srcPort: number;
  dstPort: number;
  length: number;
  checksum: string;
}

export interface ICMPHeader {
  type: number; // 8 = Echo Request, 0 = Echo Reply, 3 = Dest Unreachable
  typeName: string;
  code: number;
  checksum: string;
  identifier?: number;
  seqNumber?: number;
}

export interface ARPHeader {
  hardwareType: number; // 1 = Ethernet
  protocolType: string; // 0x0800 IPv4
  hardwareSize: number; // 6
  protocolSize: number; // 4
  opcode: number; // 1 = Request, 2 = Reply
  opcodeName: string;
  senderMac: string;
  senderIp: string;
  targetMac: string;
  targetIp: string;
}

export interface DNSData {
  transactionId: string;
  flags: {
    isResponse: boolean;
    opcode: string;
    authoritative: boolean;
    truncated: boolean;
    recursionDesired: boolean;
    recursionAvailable: boolean;
    responseCode: string;
  };
  questionsCount: number;
  answersCount: number;
  questions?: Array<{ name: string; type: string; class: string }>;
  answers?: Array<{ name: string; type: string; ttl: number; data: string }>;
}

export interface HTTPData {
  type: 'REQUEST' | 'RESPONSE';
  method?: string;
  path?: string;
  version: string;
  statusCode?: number;
  statusText?: string;
  headers: Record<string, string>;
  bodyPreview?: string;
}

export interface TLSData {
  recordType: string; // "Handshake", "Application Data", "Alert"
  version: string; // "TLS 1.2", "TLS 1.3"
  handshakeType?: string; // "Client Hello", "Server Hello"
  serverNameIndication?: string; // SNI hostname e.g. "google.com"
  cipherSuites?: string[];
}

export interface Packet {
  id: number;
  timestamp: number; // Milliseconds Unix epoch
  timeStr: string; // HH:mm:ss.SSS
  relTime: number; // Seconds since capture start
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  protocol: ProtocolType;
  length: number; // Bytes
  info: string;
  direction?: 'INCOMING' | 'OUTGOING' | 'LOCAL' | 'TRANSIT';
  
  // Layer details
  ethernet?: EthernetHeader;
  ip?: IPv4Header;
  ipv6?: IPv6Header;
  tcp?: TCPHeader;
  udp?: UDPHeader;
  icmp?: ICMPHeader;
  arp?: ARPHeader;
  dns?: DNSData;
  http?: HTTPData;
  tls?: TLSData;
  
  // Payload & Raw data
  payloadHex?: string;
  payloadAscii?: string;
  rawHex?: string;
  rawAscii?: string;
}

export interface NetworkInterface {
  id: string;
  name: string;
  displayName: string;
  ip4?: string;
  ip6?: string;
  mac: string;
  netmask?: string;
  type: 'ethernet' | 'wifi' | 'loopback' | 'virtual' | 'other';
  isDefault?: boolean;
  status: 'up' | 'down';
}

export interface CaptureStatistics {
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  averagePacketSize: number;
  protocolCounts: {
    TCP: number;
    UDP: number;
    ICMP: number;
    ARP: number;
    DNS: number;
    HTTP: number;
    HTTPS: number;
    TLS: number;
    OTHER: number;
  };
  ipCounts: {
    sources: Record<string, number>;
    destinations: Record<string, number>;
    conversations: Record<string, number>; // "IP1 <-> IP2"
  };
  portCounts: Record<number, number>;
  packetSizeDistribution: {
    '0-64': number;
    '65-128': number;
    '129-512': number;
    '513-1024': number;
    '1025-1518': number;
    '1519+': number;
  };
  directionCounts: {
    INCOMING: number;
    OUTGOING: number;
    LOCAL: number;
    TRANSIT: number;
  };
}

export interface CaptureSession {
  id: string;
  name: string;
  interfaceName: string;
  startTime: number;
  endTime?: number;
  packetCount: number;
  totalBytes: number;
  bpfFilter?: string;
  status: 'running' | 'stopped' | 'imported';
  statistics?: CaptureStatistics;
}

export type CaptureMode = 'LIVE_INTERFACE' | 'SIMULATION' | 'PCAP_IMPORT';
