# 🛠️ Python Network Tools

A collection of lightweight CLI utilities for network reconnaissance and analysis.  
Built for learning purposes — covers the same techniques used by tools like `nmap`, `netstat`, and Wireshark under the hood.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

---

## 📦 Tools

| Script | Description |
|--------|-------------|
| `ping_sweep.py` | ICMP host discovery across a subnet or IP range |
| `tcp_scanner.py` | Multi-threaded TCP port scanner with banner grabbing |
| `tcp_sessions.py` | Live TCP session monitor with process names and state info |

---

## ⚙️ Requirements

```bash
pip install psutil   # required only for tcp_sessions.py
```

Python 3.10+ required (uses `int | None` type union syntax).

---

## 🚀 Usage

### 1. Ping Sweep — host discovery

```bash
# Scan entire subnet
python ping_sweep.py 192.168.1.0/24

# Scan IP range
python ping_sweep.py 192.168.1.1-192.168.1.50

# With hostname resolution
python ping_sweep.py 192.168.1.0/24 -r

# More threads = faster scan
python ping_sweep.py 10.0.0.0/24 -t 200
```

**Example output:**
```
=======================================================
  Ping Sweep
=======================================================
  Target  : 192.168.1.0/24
  Hosts   : 254
  Threads : 150

  IP                 STATUS     HOSTNAME
  ---------------------------------------------------
  192.168.1.1        alive      router.local
  192.168.1.10       alive      desktop-pc
  192.168.1.42       alive
=======================================================
  Done. 3/254 host(s) alive.
```

---

### 2. TCP Port Scanner — open port detection

```bash
# Scan default ports 1–1024
python tcp_scanner.py 192.168.1.1

# Scan specific ports
python tcp_scanner.py 192.168.1.1 -p 22 80 443 8080

# Scan a custom range
python tcp_scanner.py 192.168.1.1 -p 1-65535

# Control thread count
python tcp_scanner.py 192.168.1.1 -p 1-1024 -t 200
```

**Example output:**
```
=======================================================
  TCP Port Scanner
=======================================================
  Target  : 192.168.1.1 (192.168.1.1)
  Ports   : 1024 (1–1024)
  Threads : 100

  PORT     STATE    SERVICE      BANNER
  ---------------------------------------------------
  22       open     SSH          SSH-2.0-OpenSSH_8.9
  80       open     HTTP
  443      open     HTTPS
=======================================================
  Done. 3 open port(s) found.
```

---

### 3. TCP Session Analyzer — live connection monitor

```bash
# Show all TCP connections on this machine
python tcp_sessions.py

# Filter by state
python tcp_sessions.py -s ESTABLISHED

# Filter by port
python tcp_sessions.py -p 443

# Resolve remote IPs to hostnames
python tcp_sessions.py -r

# Live mode (refresh every 2 sec)
python tcp_sessions.py --watch

# Show stats summary
python tcp_sessions.py --summary
```

> ⚠️ Requires `sudo` on Linux/macOS to see all processes.

**Example output:**
```
  TCP Session Analyzer  2026-04-27 14:00:00
  OS: Linux 6.5.0  |  Connections: 12

  PROCESS        STATE          LOCAL ADDRESS          REMOTE ADDRESS
  ----------------------------------------------------------------
  chrome         ESTABLISHED    192.168.1.5:52341      142.250.74.46:443
  sshd           ESTABLISHED    192.168.1.5:22         192.168.1.100:49200
  python3        LISTEN         0.0.0.0:8080           —
```

---

## 🧠 How it works (concepts)

| Tool | Key concept |
|------|-------------|
| `ping_sweep` | Sends ICMP Echo Request via `subprocess ping`. Threads allow parallel scanning. |
| `tcp_scanner` | Uses `socket.connect_ex()` — attempts a TCP 3-way handshake. If port responds → open. |
| `tcp_sessions` | Reads kernel's socket table via `psutil.net_connections()`. Same data as `netstat -an`. |

---

## ⚠️ Legal notice

These tools are intended for **educational purposes** and use on networks **you own or have permission to test**.  
Unauthorized scanning is illegal in most jurisdictions.

---

## 📚 Related topics

- TCP/IP fundamentals: RFC 793 (TCP), RFC 792 (ICMP)
- CCNA 200-301 — Network reconnaissance attacks (Vol. 2, Ch. 4)
- `nmap` — the professional tool these scripts are inspired by
