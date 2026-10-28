"""
NetScope Packet Analyzer
Dissects raw Scapy packets into layered structures (Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS).
"""

import datetime
from typing import Dict, Any, Tuple


def format_hex_ascii(raw_bytes: bytes) -> Tuple[str, str]:
    hex_parts = [f"{b:02x}" for b in raw_bytes]
    ascii_parts = [chr(b) if 32 <= b <= 126 else "." for b in raw_bytes]
    return " ".join(hex_parts), "".join(ascii_parts)


def analyze_scapy_packet(packet, packet_id: int, start_time: float) -> Dict[str, Any]:
    """
    Convert a Scapy packet into a JSON-serializable dictionary.
    """
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
    from scapy.packet import Raw

    now = datetime.datetime.now()
    time_str = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"
    rel_time = round(datetime.datetime.now().timestamp() - start_time, 4)

    pkt_len = len(packet)
    raw_bytes = bytes(packet)
    raw_hex, raw_ascii = format_hex_ascii(raw_bytes)

    result: Dict[str, Any] = {
        "id": packet_id,
        "timestamp": int(now.timestamp() * 1000),
        "timeStr": time_str,
        "relTime": rel_time,
        "srcIp": "0.0.0.0",
        "dstIp": "0.0.0.0",
        "protocol": "OTHER",
        "length": pkt_len,
        "info": f"Packet {packet_id}: {pkt_len} bytes",
        "direction": "UNKNOWN",
        "rawHex": raw_hex,
        "rawAscii": raw_ascii,
        "details": {}
    }

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        eth_type_hex = f"0x{eth.type:04x}"
        eth_type_desc = eth_type_hex
        if eth.type == 0x0800:
            eth_type_desc += " (IPv4)"
        elif eth.type == 0x0806:
            eth_type_desc += " (ARP)"
        elif eth.type == 0x86dd:
            eth_type_desc += " (IPv6)"

        result["ethernet"] = {
            "srcMac": eth.src,
            "dstMac": eth.dst,
            "etherType": eth_type_desc
        }

    # ARP Layer
    if packet.haslayer(ARP):
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["srcIp"] = arp.psrc
        result["dstIp"] = arp.pdst
        op_name = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"Opcode {arp.op}"

        result["arp"] = {
            "hardwareType": arp.hwtype,
            "protocolType": f"0x{arp.ptype:04x}",
            "hardwareSize": arp.hwlen,
            "protocolSize": arp.plen,
            "opcode": arp.op,
            "opcodeName": op_name,
            "senderMac": arp.hwsrc,
            "senderIp": arp.psrc,
            "targetMac": arp.hwdst,
            "targetIp": arp.pdst
        }
        if arp.op == 1:
            result["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            result["info"] = f"{arp.psrc} is at {arp.hwsrc}"
        return result

    # IPv4 Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        result["srcIp"] = ip.src
        result["dstIp"] = ip.dst

        proto_name = "Unknown"
        if ip.proto == 6:
            proto_name = "TCP"
        elif ip.proto == 17:
            proto_name = "UDP"
        elif ip.proto == 1:
            proto_name = "ICMP"

        result["ip"] = {
            "version": ip.version,
            "ihl": ip.ihl,
            "tos": ip.tos,
            "totalLength": ip.len,
            "identification": ip.id,
            "flags": {
                "reserved": bool(ip.flags.val & 0x4),
                "dontFragment": bool(ip.flags.val & 0x2),
                "moreFragments": bool(ip.flags.val & 0x1)
            },
            "fragmentOffset": ip.frag,
            "ttl": ip.ttl,
            "protocol": ip.proto,
            "protocolName": proto_name,
            "headerChecksum": f"0x{ip.chksum:04x}",
            "srcIp": ip.src,
            "dstIp": ip.dst
        }

    # IPv6 Layer
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        result["srcIp"] = ip6.src
        result["dstIp"] = ip6.dst
        result["ipv6"] = {
            "version": ip6.version,
            "trafficClass": ip6.tc,
            "flowLabel": ip6.fl,
            "payloadLength": ip6.plen,
            "nextHeader": ip6.nh,
            "nextHeaderName": str(ip6.nh),
            "hopLimit": ip6.hlim,
            "srcIp": ip6.src,
            "dstIp": ip6.dst
        }

    # TCP Layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["protocol"] = "TCP"
        result["srcPort"] = tcp.sport
        result["dstPort"] = tcp.dport

        flags_str = str(tcp.flags)
        flags_list = []
        if "S" in flags_str: flags_list.append("SYN")
        if "A" in flags_str: flags_list.append("ACK")
        if "F" in flags_str: flags_list.append("FIN")
        if "R" in flags_str: flags_list.append("RST")
        if "P" in flags_str: flags_list.append("PSH")
        if "U" in flags_str: flags_list.append("URG")

        flags_summary = f"[{', '.join(flags_list)}]" if flags_list else "[None]"

        result["tcp"] = {
            "srcPort": tcp.sport,
            "dstPort": tcp.dport,
            "seqNumber": tcp.seq,
            "ackNumber": tcp.ack,
            "dataOffset": tcp.dataofs,
            "flags": {
                "cwr": "C" in flags_str,
                "ece": "E" in flags_str,
                "urg": "U" in flags_str,
                "ack": "A" in flags_str,
                "psh": "P" in flags_str,
                "rst": "R" in flags_str,
                "syn": "S" in flags_str,
                "fin": "F" in flags_str
            },
            "flagsSummary": flags_summary,
            "windowSize": tcp.window,
            "checksum": f"0x{tcp.chksum:04x}",
            "urgentPointer": tcp.urgptr
        }

        # Check for HTTP / TLS
        payload_len = 0
        if packet.haslayer(Raw):
            raw_payload = bytes(packet[Raw])
            payload_len = len(raw_payload)
            p_hex, p_ascii = format_hex_ascii(raw_payload)
            result["payloadHex"] = p_hex
            result["payloadAscii"] = p_ascii

            if any(raw_payload.startswith(m) for m in [b"GET ", b"POST ", b"HTTP/1.", b"PUT ", b"HEAD "]):
                result["protocol"] = "HTTP"
                first_line = raw_payload.split(b"\r\n")[0].decode("latin-1", errors="ignore")
                result["info"] = f"HTTP {first_line[:50]}"
            elif tcp.sport == 443 or tcp.dport == 443:
                result["protocol"] = "TLS"
                result["info"] = f"TLS Record (Len={payload_len})"
                if len(raw_payload) > 5 and raw_payload[0] == 0x16:
                    htype = "Client Hello" if raw_payload[5] == 1 else "Server Hello" if raw_payload[5] == 2 else "Handshake"
                    result["info"] = f"TLS {htype}"
                    result["tls"] = {"recordType": "Handshake", "version": "TLS 1.2/1.3", "handshakeType": htype}
            else:
                result["info"] = f"{tcp.sport} → {tcp.dport} {flags_summary} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={payload_len}"
        else:
            result["info"] = f"{tcp.sport} → {tcp.dport} {flags_summary} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

        return result

    # UDP Layer
    if packet.haslayer(UDP):
        udp = packet[UDP]
        result["protocol"] = "UDP"
        result["srcPort"] = udp.sport
        result["dstPort"] = udp.dport

        result["udp"] = {
            "srcPort": udp.sport,
            "dstPort": udp.dport,
            "length": udp.len,
            "checksum": f"0x{udp.chksum:04x}"
        }

        # Check for DNS
        if packet.haslayer(DNS):
            dns = packet[DNS]
            result["protocol"] = "DNS"
            is_response = bool(dns.qr)
            tx_id = f"{dns.id:04x}"

            qname = ""
            if dns.qdcount > 0 and hasattr(dns, "qd") and dns.qd:
                try:
                    qname = dns.qd.qname.decode("latin-1", errors="ignore").rstrip(".")
                except Exception:
                    qname = "query"

            result["dns"] = {
                "transactionId": tx_id,
                "flags": {
                    "isResponse": is_response,
                    "opcode": "Standard query (0)",
                    "authoritative": bool(dns.aa),
                    "truncated": bool(dns.tc),
                    "recursionDesired": bool(dns.rd),
                    "recursionAvailable": bool(dns.ra),
                    "responseCode": "No error (0)" if dns.rcode == 0 else f"Code {dns.rcode}"
                },
                "questionsCount": dns.qdcount,
                "answersCount": dns.ancount,
                "questions": [{"name": qname, "type": "A", "class": "IN"}] if qname else []
            }

            if is_response:
                result["info"] = f"Standard query response 0x{tx_id} (Answers={dns.ancount})"
            else:
                result["info"] = f"Standard query 0x{tx_id} A {qname}"
            return result

        payload_len = len(bytes(packet[Raw])) if packet.haslayer(Raw) else 0
        result["info"] = f"{udp.sport} → {udp.dport} Len={payload_len}"
        return result

    # ICMP Layer
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result["protocol"] = "ICMP"
        type_name = "Echo (ping) request" if icmp.type == 8 else "Echo (ping) reply" if icmp.type == 0 else f"Type {icmp.type}"

        result["icmp"] = {
            "type": icmp.type,
            "typeName": type_name,
            "code": icmp.code,
            "checksum": f"0x{icmp.chksum:04x}",
            "identifier": getattr(icmp, "id", None),
            "seqNumber": getattr(icmp, "seq", None)
        }

        if icmp.type in [0, 8]:
            result["info"] = f"{type_name} id=0x{getattr(icmp, 'id', 0):04x}, seq={getattr(icmp, 'seq', 0)}"
        else:
            result["info"] = f"ICMP {type_name} (Code {icmp.code})"
        return result

    return result
