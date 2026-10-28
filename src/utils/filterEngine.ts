/**
 * NetScope — Wireshark-Style Safe Filter Parser and Evaluator
 * Evaluates filter expressions against Packet objects without ever using eval().
 */

import { Packet } from '../types/packet';

export interface FilterValidationResult {
  isValid: boolean;
  error?: string;
  ast?: FilterNode | null;
}

type TokenType = 
  | 'IDENTIFIER' 
  | 'STRING' 
  | 'NUMBER' 
  | 'IP' 
  | 'OPERATOR' 
  | 'AND' 
  | 'OR' 
  | 'NOT' 
  | 'LPAREN' 
  | 'RPAREN';

interface Token {
  type: TokenType;
  value: string;
  pos: number;
}

export type FilterNode =
  | { type: 'PROTOCOL'; protocol: string }
  | { type: 'COMPARISON'; field: string; operator: string; value: string | number }
  | { type: 'CONTAINS'; field: string; value: string }
  | { type: 'AND'; left: FilterNode; right: FilterNode }
  | { type: 'OR'; left: FilterNode; right: FilterNode }
  | { type: 'NOT'; node: FilterNode };

/**
 * Tokenize a filter expression string
 */
function tokenize(expression: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const len = expression.length;

  while (i < len) {
    const char = expression[i];

    if (/\s/.test(char)) {
      i++;
      continue;
    }

    if (char === '(') {
      tokens.push({ type: 'LPAREN', value: '(', pos: i });
      i++;
      continue;
    }

    if (char === ')') {
      tokens.push({ type: 'RPAREN', value: ')', pos: i });
      i++;
      continue;
    }

    // Comparison operators ==, !=, <=, >=, <, >
    if (char === '=' && expression[i + 1] === '=') {
      tokens.push({ type: 'OPERATOR', value: '==', pos: i });
      i += 2;
      continue;
    }
    if (char === '!' && expression[i + 1] === '=') {
      tokens.push({ type: 'OPERATOR', value: '!=', pos: i });
      i += 2;
      continue;
    }
    if (char === '<' && expression[i + 1] === '=') {
      tokens.push({ type: 'OPERATOR', value: '<=', pos: i });
      i += 2;
      continue;
    }
    if (char === '>' && expression[i + 1] === '=') {
      tokens.push({ type: 'OPERATOR', value: '>=', pos: i });
      i += 2;
      continue;
    }
    if (char === '<' || char === '>') {
      tokens.push({ type: 'OPERATOR', value: char, pos: i });
      i++;
      continue;
    }

    // Boolean && and ||
    if (char === '&' && expression[i + 1] === '&') {
      tokens.push({ type: 'AND', value: '&&', pos: i });
      i += 2;
      continue;
    }
    if (char === '|' && expression[i + 1] === '|') {
      tokens.push({ type: 'OR', value: '||', pos: i });
      i += 2;
      continue;
    }
    if (char === '!') {
      tokens.push({ type: 'NOT', value: '!', pos: i });
      i++;
      continue;
    }

    // Quoted strings
    if (char === '"' || char === "'") {
      const quote = char;
      let str = '';
      const start = i;
      i++;
      while (i < len && expression[i] !== quote) {
        str += expression[i];
        i++;
      }
      if (i < len && expression[i] === quote) {
        i++;
        tokens.push({ type: 'STRING', value: str, pos: start });
        continue;
      } else {
        throw new Error(`Unterminated string starting at index ${start}`);
      }
    }

    // Identifiers, keywords, IP addresses, numbers
    const wordStart = i;
    while (i < len && /[a-zA-Z0-9_.:-]/.test(expression[i])) {
      i++;
    }
    const word = expression.substring(wordStart, i);

    if (word.toLowerCase() === 'and') {
      tokens.push({ type: 'AND', value: 'and', pos: wordStart });
    } else if (word.toLowerCase() === 'or') {
      tokens.push({ type: 'OR', value: 'or', pos: wordStart });
    } else if (word.toLowerCase() === 'not') {
      tokens.push({ type: 'NOT', value: 'not', pos: wordStart });
    } else if (word.toLowerCase() === 'contains') {
      tokens.push({ type: 'OPERATOR', value: 'contains', pos: wordStart });
    } else if (/^\d+$/.test(word)) {
      tokens.push({ type: 'NUMBER', value: word, pos: wordStart });
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(word)) {
      tokens.push({ type: 'IP', value: word, pos: wordStart });
    } else {
      tokens.push({ type: 'IDENTIFIER', value: word, pos: wordStart });
    }
  }

  return tokens;
}

/**
 * Recursive descent parser building the Filter AST
 */
class FilterParser {
  private tokens: Token[];
  private current = 0;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  parse(): FilterNode {
    const expr = this.parseOr();
    if (this.current < this.tokens.length) {
      throw new Error(`Unexpected token "${this.tokens[this.current].value}" at index ${this.tokens[this.current].pos}`);
    }
    return expr;
  }

  private parseOr(): FilterNode {
    let node = this.parseAnd();

    while (this.match('OR')) {
      const right = this.parseAnd();
      node = { type: 'OR', left: node, right };
    }

    return node;
  }

  private parseAnd(): FilterNode {
    let node = this.parseUnary();

    while (this.match('AND')) {
      const right = this.parseUnary();
      node = { type: 'AND', left: node, right };
    }

    return node;
  }

  private parseUnary(): FilterNode {
    if (this.match('NOT')) {
      const operand = this.parseUnary();
      return { type: 'NOT', node: operand };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): FilterNode {
    if (this.match('LPAREN')) {
      const expr = this.parseOr();
      if (!this.match('RPAREN')) {
        throw new Error('Expected closing parenthesis ")"');
      }
      return expr;
    }

    const token = this.peek();
    if (!token) {
      throw new Error('Unexpected end of filter expression');
    }

    // Bare protocol name (e.g. tcp, udp, dns, icmp, arp, http, tls)
    const knownProtocols = ['tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'https', 'tls', 'ipv4', 'ipv6'];
    if (token.type === 'IDENTIFIER') {
      const lower = token.value.toLowerCase();
      
      // If followed by comparison operator, it is a field comparison (e.g. ip.src == ...)
      const nextToken = this.tokens[this.current + 1];
      if (nextToken && nextToken.type === 'OPERATOR') {
        this.current++; // consume identifier
        const op = this.tokens[this.current].value;
        this.current++; // consume operator
        
        const valToken = this.tokens[this.current];
        if (!valToken) {
          throw new Error(`Expected value after operator "${op}"`);
        }
        this.current++; // consume value

        let value: string | number = valToken.value;
        if (valToken.type === 'NUMBER') {
          value = parseInt(valToken.value, 10);
        }

        if (op === 'contains') {
          return { type: 'CONTAINS', field: lower, value: String(value) };
        }

        return {
          type: 'COMPARISON',
          field: lower,
          operator: op,
          value,
        };
      }

      // Check if bare protocol keyword
      if (knownProtocols.includes(lower)) {
        this.current++;
        return { type: 'PROTOCOL', protocol: lower.toUpperCase() };
      }

      throw new Error(`Unknown field or protocol identifier "${token.value}". Try: tcp, udp, ip.src == x.x.x.x, port == 80`);
    }

    if (token.type === 'IP') {
      this.current++;
      return { type: 'COMPARISON', field: 'ip.addr', operator: '==', value: token.value };
    }

    throw new Error(`Unexpected token "${token.value}" at position ${token.pos}`);
  }

  private match(type: TokenType): boolean {
    if (this.current < this.tokens.length && this.tokens[this.current].type === type) {
      this.current++;
      return true;
    }
    return false;
  }

  private peek(): Token | undefined {
    return this.tokens[this.current];
  }
}

/**
 * Validate syntax and return AST or helpful error message
 */
export function validateFilter(filterStr: string): FilterValidationResult {
  const trimmed = filterStr.trim();
  if (!trimmed) {
    return { isValid: true, ast: null };
  }

  try {
    const tokens = tokenize(trimmed);
    if (tokens.length === 0) {
      return { isValid: true, ast: null };
    }
    const parser = new FilterParser(tokens);
    const ast = parser.parse();
    return { isValid: true, ast };
  } catch (err: any) {
    return { isValid: false, error: err.message || 'Syntax error in filter expression' };
  }
}

/**
 * Safely evaluate an AST against a Packet
 */
export function evaluateFilterNode(node: FilterNode, packet: Packet): boolean {
  switch (node.type) {
    case 'PROTOCOL': {
      const target = node.protocol.toUpperCase();
      if (target === 'TCP') return packet.protocol === 'TCP' || !!packet.tcp;
      if (target === 'UDP') return packet.protocol === 'UDP' || !!packet.udp;
      if (target === 'ICMP') return packet.protocol === 'ICMP' || !!packet.icmp;
      if (target === 'ARP') return packet.protocol === 'ARP' || !!packet.arp;
      if (target === 'DNS') return packet.protocol === 'DNS' || !!packet.dns;
      if (target === 'HTTP') return packet.protocol === 'HTTP' || !!packet.http;
      if (target === 'HTTPS' || target === 'TLS') return packet.protocol === 'TLS' || packet.protocol === 'HTTPS' || !!packet.tls;
      if (target === 'IPV4') return !!packet.ip;
      if (target === 'IPV6') return !!packet.ipv6;
      return packet.protocol === target;
    }

    case 'COMPARISON': {
      const field = node.field.toLowerCase();
      const op = node.operator;
      const targetVal = node.value;

      let actualVal: any = undefined;

      // Map fields
      if (field === 'ip.src' || field === 'src') {
        actualVal = packet.srcIp;
      } else if (field === 'ip.dst' || field === 'dst') {
        actualVal = packet.dstIp;
      } else if (field === 'ip.addr') {
        return compareValues(packet.srcIp, op, targetVal) || compareValues(packet.dstIp, op, targetVal);
      } else if (field === 'port') {
        return compareValues(packet.srcPort, op, targetVal) || compareValues(packet.dstPort, op, targetVal);
      } else if (field === 'tcp.port') {
        if (!packet.tcp) return false;
        return compareValues(packet.tcp.srcPort, op, targetVal) || compareValues(packet.tcp.dstPort, op, targetVal);
      } else if (field === 'udp.port') {
        if (!packet.udp) return false;
        return compareValues(packet.udp.srcPort, op, targetVal) || compareValues(packet.udp.dstPort, op, targetVal);
      } else if (field === 'tcp.srcport' || field === 'srcport') {
        actualVal = packet.srcPort;
      } else if (field === 'tcp.dstport' || field === 'dstport') {
        actualVal = packet.dstPort;
      } else if (field === 'frame.len' || field === 'len' || field === 'length') {
        actualVal = packet.length;
      } else if (field === 'tcp.flags.syn') {
        actualVal = packet.tcp?.flags?.syn ? 1 : 0;
      } else if (field === 'tcp.flags.ack') {
        actualVal = packet.tcp?.flags?.ack ? 1 : 0;
      } else if (field === 'tcp.flags.fin') {
        actualVal = packet.tcp?.flags?.fin ? 1 : 0;
      } else if (field === 'tcp.flags.rst') {
        actualVal = packet.tcp?.flags?.rst ? 1 : 0;
      } else if (field === 'dns.qry.name') {
        if (!packet.dns || !packet.dns.questions) return false;
        return packet.dns.questions.some(q => compareValues(q.name.toLowerCase(), op, String(targetVal).toLowerCase()));
      } else if (field === 'http.host') {
        actualVal = packet.http?.headers?.['Host'] || packet.http?.headers?.['host'];
      }

      if (actualVal === undefined) return false;
      return compareValues(actualVal, op, targetVal);
    }

    case 'CONTAINS': {
      const field = node.field.toLowerCase();
      const search = node.value.toLowerCase();

      if (field === 'info') {
        return packet.info.toLowerCase().includes(search);
      }
      if (field === 'payload' || field === 'data') {
        return (packet.payloadAscii || '').toLowerCase().includes(search) || 
               (packet.payloadHex || '').toLowerCase().includes(search);
      }
      if (field === 'dns.qry.name' && packet.dns?.questions) {
        return packet.dns.questions.some(q => q.name.toLowerCase().includes(search));
      }
      if (field === 'http.host' && packet.http?.headers) {
        const host = packet.http.headers['Host'] || packet.http.headers['host'] || '';
        return host.toLowerCase().includes(search);
      }
      return packet.info.toLowerCase().includes(search);
    }

    case 'AND':
      return evaluateFilterNode(node.left, packet) && evaluateFilterNode(node.right, packet);

    case 'OR':
      return evaluateFilterNode(node.left, packet) || evaluateFilterNode(node.right, packet);

    case 'NOT':
      return !evaluateFilterNode(node.node, packet);

    default:
      return true;
  }
}

function compareValues(actual: any, op: string, target: any): boolean {
  if (typeof target === 'number') {
    const actNum = Number(actual);
    if (isNaN(actNum)) return false;
    switch (op) {
      case '==': return actNum === target;
      case '!=': return actNum !== target;
      case '<': return actNum < target;
      case '<=': return actNum <= target;
      case '>': return actNum > target;
      case '>=': return actNum >= target;
      default: return false;
    }
  }

  // String comparison
  const actStr = String(actual || '').toLowerCase();
  const tgtStr = String(target || '').toLowerCase();

  switch (op) {
    case '==': return actStr === tgtStr;
    case '!=': return actStr !== tgtStr;
    default: return false;
  }
}

/**
 * Filter an array of packets against a filter expression string
 */
export function filterPackets(packets: Packet[], filterStr: string): Packet[] {
  const result = validateFilter(filterStr);
  if (!result.isValid || !result.ast) {
    return packets;
  }
  return packets.filter(p => evaluateFilterNode(result.ast!, p));
}

/**
 * Common filter presets for quick learning & evaluation
 */
export const FILTER_PRESETS = [
  { label: 'All TCP Traffic', query: 'tcp', description: 'Filter all TCP segments' },
  { label: 'All UDP Traffic', query: 'udp', description: 'Filter all UDP datagrams' },
  { label: 'DNS Queries & Replies', query: 'dns', description: 'Port 53 domain name requests' },
  { label: 'HTTP Web Traffic', query: 'tcp.port == 80', description: 'Unencrypted web traffic on port 80' },
  { label: 'HTTPS / TLS Traffic', query: 'tcp.port == 443', description: 'Encrypted web sessions' },
  { label: 'ICMP Echo / Ping', query: 'icmp', description: 'Ping echo requests and replies' },
  { label: 'Address Resolution (ARP)', query: 'arp', description: 'Layer 2 MAC-to-IP mappings' },
  { label: 'TCP Handshake (SYN)', query: 'tcp.flags.syn == 1', description: 'Connection establishment packets' },
  { label: 'Large Packets (> 1000B)', query: 'frame.len > 1000', description: 'Jumbo or bulk transfer frames' },
];
