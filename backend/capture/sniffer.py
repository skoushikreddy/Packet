"""
NetScope Packet Sniffer
Scapy-powered asynchronous packet capture engine with live callback streaming.
"""

import time
import threading
from typing import Optional, Callable, List, Dict, Any


class ScapySnifferWorker:
    def __init__(self, packet_callback: Callable[[Dict[str, Any]], None]):
        self.packet_callback = packet_callback
        self.is_capturing = False
        self.selected_interface: Optional[str] = None
        self.bpf_filter: str = ""
        self.sniffer_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.current_packet_id = 1
        self.start_time = 0.0
        self.total_packets = 0
        self.total_bytes = 0

    @staticmethod
    def get_interfaces() -> List[Dict[str, Any]]:
        """
        Enumerate network interfaces using Scapy / OS
        """
        interfaces = []
        try:
            from scapy.all import get_if_list, get_if_hwaddr, get_if_addr
            if_list = get_if_list()

            for iface in if_list:
                try:
                    ip = get_if_addr(iface)
                except Exception:
                    ip = "0.0.0.0"
                try:
                    mac = get_if_hwaddr(iface)
                except Exception:
                    mac = "00:00:00:00:00:00"

                if_type = "ethernet"
                lower_name = iface.lower()
                if "lo" in lower_name:
                    if_type = "loopback"
                elif "wl" in lower_name or "wi-fi" in lower_name:
                    if_type = "wifi"

                interfaces.append({
                    "id": iface,
                    "name": iface,
                    "displayName": f"{iface} ({if_type.upper()}) - {ip}",
                    "ip4": ip if ip != "0.0.0.0" else None,
                    "mac": mac,
                    "type": if_type,
                    "isDefault": ip not in ("0.0.0.0", "127.0.0.1"),
                    "status": "up"
                })
        except Exception as e:
            print(f"[Sniffer] Interface enumeration fallback: {e}")
            interfaces = [
                {
                    "id": "eth0",
                    "name": "eth0",
                    "displayName": "eth0 (ETHERNET) - 192.168.1.105",
                    "ip4": "192.168.1.105",
                    "mac": "02:42:ac:11:00:02",
                    "type": "ethernet",
                    "isDefault": True,
                    "status": "up"
                }
            ]

        return interfaces

    def start_capture(self, iface_name: str, bpf_filter: str = "") -> bool:
        if self.is_capturing:
            return False

        self.selected_interface = iface_name
        self.bpf_filter = bpf_filter
        self.is_capturing = True
        self.stop_event.clear()
        self.current_packet_id = 1
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0

        self.sniffer_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.sniffer_thread.start()
        return True

    def stop_capture(self) -> None:
        self.is_capturing = False
        self.stop_event.set()
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.0)

    def _capture_loop(self) -> None:
        from scapy.all import sniff
        from ..analyzers.packet_analyzer import analyze_scapy_packet

        def on_packet(pkt):
            if not self.is_capturing or self.stop_event.is_set():
                return
            try:
                summary = analyze_scapy_packet(pkt, self.current_packet_id, self.start_time)
                self.current_packet_id += 1
                self.total_packets += 1
                self.total_bytes += summary.get("length", 0)
                self.packet_callback(summary)
            except Exception as ex:
                print(f"[Sniffer] Error analyzing packet: {ex}")

        try:
            kwargs = {
                "prn": on_packet,
                "store": False,
                "stop_filter": lambda _: self.stop_event.is_set()
            }
            if self.selected_interface and self.selected_interface != "default":
                kwargs["iface"] = self.selected_interface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter

            sniff(**kwargs)
        except Exception as e:
            print(f"[Sniffer] Sniffing exception: {e}")
            self.is_capturing = False
