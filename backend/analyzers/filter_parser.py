"""
NetScope Filter Parser
Translates Wireshark-style user filter expressions into safe BPF filter strings for Scapy.
Never uses eval().
"""

import re
from typing import Tuple, Optional


def translate_filter_to_bpf(expression: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate filter and translate to Berkeley Packet Filter (BPF) syntax.
    Returns: (is_valid, bpf_string, error_message)
    """
    expr = expression.strip()
    if not expr:
        return True, "", None

    # Common exact protocol matches
    protocols = {"tcp", "udp", "icmp", "arp", "ip", "ip6"}
    if expr.lower() in protocols:
        return True, expr.lower(), None

    # Handle DNS
    if expr.lower() == "dns":
        return True, "port 53", None

    # Handle HTTP / HTTPS
    if expr.lower() == "http":
        return True, "tcp port 80", None
    if expr.lower() in ("https", "tls"):
        return True, "tcp port 443", None

    # Match ip.src == x.x.x.x
    m_src = re.match(r"^ip\.src\s*==\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", expr, re.IGNORECASE)
    if m_src:
        return True, f"src host {m_src.group(1)}", None

    # Match ip.dst == x.x.x.x
    m_dst = re.match(r"^ip\.dst\s*==\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", expr, re.IGNORECASE)
    if m_dst:
        return True, f"dst host {m_dst.group(1)}", None

    # Match ip.addr == x.x.x.x
    m_host = re.match(r"^ip\.(?:addr\s*==\s*)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", expr, re.IGNORECASE)
    if m_host:
        return True, f"host {m_host.group(1)}", None

    # Match tcp.port == N
    m_tcpport = re.match(r"^tcp\.port\s*==\s*(\d{1,5})$", expr, re.IGNORECASE)
    if m_tcpport:
        port = int(m_tcpport.group(1))
        if 1 <= port <= 65535:
            return True, f"tcp port {port}", None
        return False, None, "Port must be between 1 and 65535"

    # Match udp.port == N
    m_udpport = re.match(r"^udp\.port\s*==\s*(\d{1,5})$", expr, re.IGNORECASE)
    if m_udpport:
        port = int(m_udpport.group(1))
        if 1 <= port <= 65535:
            return True, f"udp port {port}", None
        return False, None, "Port must be between 1 and 65535"

    # Match port == N
    m_port = re.match(r"^port\s*==\s*(\d{1,5})$", expr, re.IGNORECASE)
    if m_port:
        port = int(m_port.group(1))
        if 1 <= port <= 65535:
            return True, f"port {port}", None
        return False, None, "Port must be between 1 and 65535"

    # Match tcp.flags.syn == 1
    if re.match(r"^tcp\.flags\.syn\s*==\s*1$", expr, re.IGNORECASE):
        return True, "tcp[tcpflags] & tcp-syn != 0", None

    # Match tcp.flags.ack == 1
    if re.match(r"^tcp\.flags\.ack\s*==\s*1$", expr, re.IGNORECASE):
        return True, "tcp[tcpflags] & tcp-ack != 0", None

    # If the user directly entered a standard BPF string like 'tcp and port 80'
    bpf_tokens = re.split(r"\s+", expr.lower())
    safe_keywords = {"tcp", "udp", "icmp", "arp", "ip", "src", "dst", "host", "port", "and", "or", "not", "&&", "||", "net"}
    if all(t in safe_keywords or re.match(r"^\d+$", t) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t) for t in bpf_tokens):
        return True, expr, None

    return False, None, f"Unsupported filter expression: '{expr}'. Supported: tcp, udp, icmp, arp, dns, ip.src == x.x.x.x, ip.dst == x.x.x.x, tcp.port == 443"
