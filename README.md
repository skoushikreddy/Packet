# NetScope — Network Packet Analyser & Observability Dashboard
**Academic Computer Networks (CN) Capstone Project**

NetScope is a modern, high-performance web application and packet inspection workstation inspired by Wireshark and modern cloud network observability platforms. Built with React 19, TypeScript, Tailwind CSS, Recharts, and Python with Scapy & Flask, it captures network packets from authorized network adapters, performs deep protocol header dissection across Layers 2 through 7, visualizes network traffic telemetry in real-time, and archives sessions in a persistent SQLite database.

---

## 1. Project Objectives & Academic Concepts Demonstrated

NetScope was architected to demonstrate core Computer Networks (CN) syllabus principles:
- **OSI 7-Layer & TCP/IP 4-Layer Models:** Hierarchical packet encapsulation and decapsulation from physical wire bits to application data.
- **Ethernet II Frames & Physical Addressing:** 48-bit MAC addresses (`Source MAC`, `Destination MAC`), EtherTypes (`0x0800 IPv4`, `0x0806 ARP`, `0x86dd IPv6`).
- **Address Resolution Protocol (ARP):** Local broadcast resolution (`Who has 192.168.1.1? Tell 192.168.1.105`) and unicast reply mapping.
- **Internet Protocol (IPv4 & IPv6):** Header Length (IHL), Total Length, Identification, Don't Fragment (DF) flags, Time to Live (TTL) hop count tracking, protocol numbers, and IP checksum verification.
- **Transmission Control Protocol (TCP):** Connection-oriented virtual circuits, sequence numbers, acknowledgment numbers, flow control window size, and 9-bit control flag analysis (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
- **TCP 3-Way Handshake:** Explicit tracking of client `[SYN]`, server `[SYN, ACK]`, and client `[ACK]`.
- **User Datagram Protocol (UDP):** Connectionless datagram delivery, length, and checksum validation.
- **Domain Name System (DNS):** Port 53 recursive query messages, Transaction IDs, QR response flags, Question sections, and Type A IPv4 answer records.
- **Hypertext Transfer Protocol (HTTP/1.1):** REST request methods (`GET`, `POST`), request paths, status codes (`200 OK`, `404 Not Found`), and HTTP header parsing.
- **Transport Layer Security (TLS 1.2/1.3):** Non-intrusive inspection of TLS handshake records, Server Name Indication (SNI hostname), and negotiated cipher suites.
- **Hexadecimal & ASCII Dissection:** 16-bytes per line canonical hex dump with matching ASCII characters and byte offsets.

---

## 2. Technology Stack

### Frontend
- **React 19 & TypeScript:** Type-safe modular user interface and state management.
- **Vite:** High-speed development bundler and middleware runner.
- **Tailwind CSS:** Dark navy cybersecurity theme with cyan, sky, and emerald accents.
- **Recharts:** Interactive AreaCharts, LineCharts, Pie/Donut charts, and BarCharts.
- **Lucide Icons:** Consistent networking and diagnostic iconography.

### Backend & Packet Engine
- **Full-Stack Node/Express:** Built-in dev server on port 3000 running REST endpoints, WebSockets (`/ws/packets`), and synthetic trace generators.
- **Python 3 Backend (Standalone):** Flask, Flask-SocketIO, and Scapy `AsyncSniffer` capturing real packets via Npcap (Windows) or raw sockets (Linux).
- **SQLite Database:** Local persistent storage for capture sessions, timestamps, byte volumes, and packet records.
- **libpcap v2.4 Binary Engine:** Full binary reader and generator for standard `.pcap` files compatible with Wireshark and tcpdump.

---

## 3. Windows Installation & Execution Guide (Step-by-Step)

### Step 1: Install Python 3
1. Download Python 3.10+ from [python.org](https://www.python.org/downloads/).
2. **Important:** Check the box **"Add Python to PATH"** during installation.

### Step 2: Install Npcap (Required for Windows Packet Capture)
1. Download Npcap from [npcap.com](https://npcap.com/#download).
2. Run the installer with Administrator rights.
3. In the installation options, check:
   - **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"**
   - **"Install Npcap in WinPcap API-compatible Mode"** *(Crucial for Scapy)*.

### Step 3: Launch Node.js Frontend & Full-Stack Server
Open PowerShell or Command Prompt in the project folder:
```powershell
# 1. Install Node dependencies
npm install

# 2. Start NetScope full-stack application
npm run dev
```
Open your browser at: **`http://localhost:3000`**

### Step 4: Run the Standalone Python Scapy Backend (Optional for Real Windows Sniffing)
1. Open PowerShell **as Administrator**.
2. Navigate to `backend`:
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
The Python backend will listen on `http://127.0.0.1:5000` and stream live captured frames via SocketIO.

---

## 4. Linux Installation Guide

```bash
# 1. Install system prerequisites and libpcap
sudo apt update
sudo apt install -y nodejs npm python3 python3-pip python3-venv libpcap-dev

# 2. Run frontend full-stack server
npm install
npm run dev

# 3. Grant raw socket sniffing capabilities without root (Recommended)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# 4. Or run Python backend with sudo
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

---

## 5. How to Demonstrate the Project for CN Academic Evaluation / Viva

1. **Overview Dashboard:**
   - Explain the 8 KPI cards: Total Packets, Volume in KB/MB, Average Packet Size, Packets Per Second (PPS), TCP/UDP/ICMP counts, and Unique Communicating IPs.
   - Show the real-time traffic volume area chart and protocol breakdown pie chart.
2. **Live Capture Workstation:**
   - Select your network interface from the top navigation dropdown.
   - Click **Start Capture** to demonstrate live stream capture.
   - Click **Pause Stream** to freeze the table display while inspecting a specific packet.
   - Apply Wireshark-compatible display filters in the filter bar (e.g. `tcp`, `udp`, `icmp`, `dns`, `ip.src == 192.168.1.1`, `tcp.port == 443`).
   - Click any packet in the table: demonstrate the **collapsible protocol layer tree** (Ethernet II → IPv4 → TCP/UDP/ICMP → Application Layer) and the canonical **16-byte Hex Dump + ASCII view**.
3. **Deep Packet Explorer:**
   - Demonstrate multi-attribute search across IPs, ports, and payload text.
   - Filter by protocol pill buttons, direction (Incoming vs Outgoing), and sort by packet size or timestamp.
4. **Protocol Analysis & Traffic Observability:**
   - Walk through the OSI reference model mapping table.
   - Show the **Most Frequently Used Ports** chart (Ports 80, 443, 53) and the **Top IP Conversations Matrix** (bidirectional communicating pairs).
   - Show the **TCP vs UDP Traffic Intensity** line chart and **Ingress vs Egress Bandwidth** bar chart.
5. **PCAP Import & Academic Trace Library:**
   - Demonstrate the drag-and-drop `.pcap` parser.
   - Click **"Load Full Trace"** or **"Load DNS Trace"** to demonstrate instant analysis of reference traces with zero driver dependencies.
6. **Academic Project Report & Wireshark Export:**
   - Click **Export** in the top navigation.
   - Download the captured session as a binary **`.pcap`** file: demonstrate that it can be directly opened in Wireshark.
   - Open the **Academic CN Project Report** tab: view and print/save the formatted laboratory report with executive summary, observations, and student/evaluator sign-off sections.
7. **Academic Guide & Viva Voce Q&A:**
   - Open the **Academic & CN Concepts** tab to show the interactive OSI vs TCP/IP layer comparison diagram, the TCP 3-way handshake visualizer, header structure specifications, and curated viva voce questions.

---

## 6. Supported Filter Syntax

The NetScope safe filter parser tokenizes and evaluates expressions using an Abstract Syntax Tree (AST) with zero `eval()` calls:

| Filter Expression | Description |
| :--- | :--- |
| `tcp` | Matches all TCP segments |
| `udp` | Matches all UDP datagrams |
| `icmp` | Matches ping echo requests and replies |
| `dns` | Matches domain name resolution traffic |
| `arp` | Matches address resolution frames |
| `tcp.port == 443` | Matches HTTPS / TLS traffic on port 443 |
| `udp.port == 53` | Matches DNS queries and responses |
| `ip.src == 192.168.1.10` | Matches packets originating from specified IP |
| `ip.dst == 8.8.8.8` | Matches packets destined to Google DNS |
| `frame.len > 500` | Matches frames larger than 500 bytes |
| `tcp.flags.syn == 1` | Matches TCP connection establishment requests |
| `tcp and port 80` | Logical combination of protocol and port |

---

## 7. Security, Privacy & Ethical Guardrails

- **Local Scope Only:** Captured packets remain entirely on the local client machine and local SQLite database; no packet data is transmitted to external servers.
- **No TLS Decryption:** In accordance with ethical standards, NetScope does not intercept or decrypt private TLS application payloads; only unencrypted handshake metadata (SNI, cipher suites) is inspected.
- **Authorization Reminder:** Always obtain permission before monitoring network traffic on shared or institutional networks.
