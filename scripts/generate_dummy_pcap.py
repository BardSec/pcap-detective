"""Generate a dummy PCAP file that triggers all 20 Detective analyzers."""

import struct
import random
import time
from scapy.all import (
    Ether, Dot1Q, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ARP,
    BOOTP, DHCP, wrpcap, RandMAC, conf
)

conf.verb = 0
packets = []

# Timestamps: simulate ~5 minutes of traffic
BASE_TIME = 1700000000.0

def ts(offset):
    return BASE_TIME + offset

# --- Network layout ---
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 60)]
EXTERNAL_IPS = ["203.0.113.10", "198.51.100.20", "192.0.2.50", "203.0.113.99"]
DNS_SERVER = "10.0.1.2"
DHCP_SERVER = "10.0.1.1"
PUBLIC_DNS = ["8.8.8.8", "1.1.1.1"]

# --- 1. Broadcast Storm (broadcast_storm.py) ---
# 150+ ARP broadcasts in 1 second from single source
for i in range(160):
    p = Ether(src="aa:bb:cc:00:00:01", dst="ff:ff:ff:ff:ff:ff") / \
        ARP(psrc="10.0.1.10", pdst=f"10.0.1.{200+i%50}")
    p.time = ts(0 + i * 0.005)
    packets.append(p)

# --- 2. C2 Beaconing (c2_beacon.py) ---
# Regular outbound packets every 30s with <15% variance, 10+ packets
for i in range(12):
    jitter = random.uniform(-1, 1)  # small jitter, CV < 0.15
    p = Ether() / IP(src="10.0.1.15", dst="203.0.113.10") / \
        TCP(sport=49000, dport=443, flags="PA") / Raw(load=b"beacon" * 5)
    p.time = ts(10 + i * 30 + jitter)
    packets.append(p)
    # Small response
    r = Ether() / IP(src="203.0.113.10", dst="10.0.1.15") / \
        TCP(sport=443, dport=49000, flags="A") / Raw(load=b"ok")
    r.time = ts(10.5 + i * 30 + jitter)
    packets.append(r)

# --- 3. CIPA Compliance (cipa_compliance.py) ---
# HTTPS connection without filter product signatures
tls_client_hello = bytes([
    0x16, 0x03, 0x01, 0x00, 0x40,  # TLS record header
    0x01, 0x00, 0x00, 0x3c,        # ClientHello handshake
    0x03, 0x03,                      # TLS 1.2
]) + b'\x00' * 32 + bytes([        # random
    0x00,                            # session id length
    0x00, 0x02, 0xc0, 0x2f,        # cipher suites
    0x01, 0x00,                      # compression
    0x00, 0x11,                      # extensions length
    0x00, 0x00,                      # SNI extension
    0x00, 0x0d,                      # extension length
    0x00, 0x0b,                      # SNI list length
    0x00,                            # host_name type
    0x00, 0x08,                      # name length
]) + b'evil.com'

p = Ether() / IP(src="10.0.1.20", dst="198.51.100.20") / \
    TCP(sport=50000, dport=443, flags="PA") / Raw(load=tls_client_hello)
p.time = ts(15)
packets.append(p)

# --- 4. Cleartext Credentials (cleartext.py) ---
# HTTP Basic Auth
import base64
creds_b64 = base64.b64encode(b"admin:P@ssw0rd123").decode()
http_basic = f"GET /admin HTTP/1.1\r\nHost: 10.0.1.30\r\nAuthorization: Basic {creds_b64}\r\n\r\n"
p = Ether() / IP(src="10.0.1.11", dst="10.0.1.30") / \
    TCP(sport=51000, dport=80, flags="PA") / Raw(load=http_basic.encode())
p.time = ts(20)
packets.append(p)

# HTTP POST with password
http_post = "POST /login HTTP/1.1\r\nHost: 10.0.1.30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=jdoe&password=Secret123&submit=Login"
p = Ether() / IP(src="10.0.1.12", dst="10.0.1.30") / \
    TCP(sport=51001, dport=8080, flags="PA") / Raw(load=http_post.encode())
p.time = ts(21)
packets.append(p)

# FTP credentials
ftp_user = Ether() / IP(src="10.0.1.13", dst="10.0.1.30") / \
    TCP(sport=51002, dport=21, flags="PA") / Raw(load=b"USER ftpuser\r\n")
ftp_user.time = ts(22)
packets.append(ftp_user)
ftp_pass = Ether() / IP(src="10.0.1.13", dst="10.0.1.30") / \
    TCP(sport=51002, dport=21, flags="PA") / Raw(load=b"PASS ftppass123\r\n")
ftp_pass.time = ts(23)
packets.append(ftp_pass)

# SMTP AUTH
smtp_auth = Ether() / IP(src="10.0.1.14", dst="10.0.1.30") / \
    TCP(sport=51003, dport=587, flags="PA") / Raw(load=b"AUTH LOGIN\r\n")
smtp_auth.time = ts(24)
packets.append(smtp_auth)
smtp_user = Ether() / IP(src="10.0.1.14", dst="10.0.1.30") / \
    TCP(sport=51003, dport=587, flags="PA") / Raw(load=base64.b64encode(b"smtpuser") + b"\r\n")
smtp_user.time = ts(24.5)
packets.append(smtp_user)
smtp_pass = Ether() / IP(src="10.0.1.14", dst="10.0.1.30") / \
    TCP(sport=51003, dport=587, flags="PA") / Raw(load=base64.b64encode(b"smtppass") + b"\r\n")
smtp_pass.time = ts(25)
packets.append(smtp_pass)

# --- 5. Connection Failures (connection_failures.py) ---
# ICMP Unreachable - firewall codes
for code in [9, 10, 13]:
    p = Ether() / IP(src="10.0.1.1", dst="10.0.1.20") / \
        ICMP(type=3, code=code) / IP(src="10.0.1.20", dst="203.0.113.50") / TCP(dport=443)
    p.time = ts(30 + code)
    packets.append(p)

# TCP RSTs (>5 from same dest)
for i in range(8):
    p = Ether() / IP(src="198.51.100.20", dst="10.0.1.20") / \
        TCP(sport=443, dport=52000 + i, flags="R")
    p.time = ts(35 + i * 0.5)
    packets.append(p)

# Unanswered SYNs (silently dropped)
for i in range(5):
    p = Ether() / IP(src="10.0.1.20", dst="203.0.113.99") / \
        TCP(sport=53000 + i, dport=8443, flags="S")
    p.time = ts(40 + i)
    packets.append(p)

# --- 6. Content Filter Bypass (content_filter_bypass.py) ---
# DNS query to public resolver
for dns_ip in PUBLIC_DNS:
    p = Ether() / IP(src="10.0.1.21", dst=dns_ip) / \
        UDP(sport=54000, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
    p.time = ts(50)
    packets.append(p)

# VPN domain queries
for domain in ["nordvpn.com", "expressvpn.com", "psiphon.ca"]:
    p = Ether() / IP(src="10.0.1.22", dst=DNS_SERVER) / \
        UDP(sport=54001, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    p.time = ts(51)
    packets.append(p)

# DoT connection (port 853)
p = Ether() / IP(src="10.0.1.23", dst="1.1.1.1") / \
    TCP(sport=54002, dport=853, flags="S")
p.time = ts(52)
packets.append(p)

# --- 7. Data Staging (data_staging.py) ---
# Internal-to-internal large transfer (>5MB)
staging_data = b"X" * 1400
for i in range(4000):  # ~5.6MB
    p = Ether() / IP(src="10.0.1.25", dst="10.0.1.26") / \
        TCP(sport=55000, dport=445, flags="PA") / Raw(load=staging_data)
    p.time = ts(60 + i * 0.01)
    packets.append(p)

# Then external exfil from staging target (>1MB within 10 min)
for i in range(1000):  # ~1.4MB
    p = Ether() / IP(src="10.0.1.26", dst="203.0.113.10") / \
        TCP(sport=55001, dport=443, flags="PA") / Raw(load=staging_data)
    p.time = ts(120 + i * 0.01)
    packets.append(p)

# --- 8. DGA Detection (dga_detection.py) ---
# High-entropy random domain queries
dga_domains = [
    "xkjvqpzwbnmfklsx.com",
    "qwrtypsdflghjkzxcvb.net",
    "a3b7c9d2e8f1g5h4k6.org",
    "mnbvcxzlkjhgfdsa98.info",
    "p7q2r9s4t1u6v3w8x5.biz",
]
for i, domain in enumerate(dga_domains):
    p = Ether() / IP(src="10.0.1.27", dst=DNS_SERVER) / \
        UDP(sport=56000, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    p.time = ts(140 + i)
    packets.append(p)

# --- 9. DHCP Analysis (dhcp_analysis.py) ---
client_mac = "aa:bb:cc:11:22:33"
# DISCOVER
p = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / \
    IP(src="0.0.0.0", dst="255.255.255.255") / \
    UDP(sport=68, dport=67) / \
    BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=0x12345678) / \
    DHCP(options=[("message-type", "discover"), ("hostname", "student-pc"), "end"])
p.time = ts(150)
packets.append(p)

# OFFER
p = Ether(src="00:11:22:33:44:55", dst=client_mac) / \
    IP(src=DHCP_SERVER, dst="10.0.1.100") / \
    UDP(sport=67, dport=68) / \
    BOOTP(op=2, yiaddr="10.0.1.100", siaddr=DHCP_SERVER, chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=0x12345678) / \
    DHCP(options=[("message-type", "offer"), ("server_id", DHCP_SERVER), ("lease_time", 86400), "end"])
p.time = ts(150.5)
packets.append(p)

# REQUEST
p = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / \
    IP(src="0.0.0.0", dst="255.255.255.255") / \
    UDP(sport=68, dport=67) / \
    BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=0x12345678) / \
    DHCP(options=[("message-type", "request"), ("server_id", DHCP_SERVER), ("requested_addr", "10.0.1.100"), "end"])
p.time = ts(151)
packets.append(p)

# ACK
p = Ether(src="00:11:22:33:44:55", dst=client_mac) / \
    IP(src=DHCP_SERVER, dst="10.0.1.100") / \
    UDP(sport=67, dport=68) / \
    BOOTP(op=2, yiaddr="10.0.1.100", siaddr=DHCP_SERVER, chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=0x12345678) / \
    DHCP(options=[("message-type", "ack"), ("server_id", DHCP_SERVER), ("lease_time", 86400), "end"])
p.time = ts(151.5)
packets.append(p)

# --- 10. DNS Health (dns_health.py) ---
# NXDOMAIN
p = Ether() / IP(src=DNS_SERVER, dst="10.0.1.28") / \
    UDP(sport=53, dport=57000) / DNS(id=100, qr=1, rcode=3, qd=DNSQR(qname="blocked.example.com"))
p.time = ts(155)
packets.append(p)
# Query for it
pq = Ether() / IP(src="10.0.1.28", dst=DNS_SERVER) / \
    UDP(sport=57000, dport=53) / DNS(id=100, rd=1, qd=DNSQR(qname="blocked.example.com"))
pq.time = ts(154.9)
packets.append(pq)

# SERVFAIL
p = Ether() / IP(src=DNS_SERVER, dst="10.0.1.28") / \
    UDP(sport=53, dport=57001) / DNS(id=101, qr=1, rcode=2, qd=DNSQR(qname="broken.example.com"))
p.time = ts(156)
packets.append(p)
pq = Ether() / IP(src="10.0.1.28", dst=DNS_SERVER) / \
    UDP(sport=57001, dport=53) / DNS(id=101, rd=1, qd=DNSQR(qname="broken.example.com"))
pq.time = ts(155.9)
packets.append(pq)

# REFUSED
p = Ether() / IP(src=DNS_SERVER, dst="10.0.1.28") / \
    UDP(sport=53, dport=57002) / DNS(id=102, qr=1, rcode=5, qd=DNSQR(qname="refused.example.com"))
p.time = ts(157)
packets.append(p)
pq = Ether() / IP(src="10.0.1.28", dst=DNS_SERVER) / \
    UDP(sport=57002, dport=53) / DNS(id=102, rd=1, qd=DNSQR(qname="refused.example.com"))
pq.time = ts(156.9)
packets.append(pq)

# --- 11. DNS Tunnel (dns_tunnel.py) ---
# Long high-entropy subdomain TXT queries
tunnel_domains = [
    "a3b7c9d2e8f1g5h4k6m8n2p4q7r1s5t9u3v6w0x8y2z4a3b7c9d2.evil-tunnel.com",
    "x5y1z3a7b2c8d4e6f9g1h3j5k7l2m4n8p1q3r5s7t9u2v4w6x8y1.evil-tunnel.com",
    "m9n3p7q1r5s8t2u6v0w4x8y2z6a1b5c9d3e7f1g5h9j3k7l1m5n9.evil-tunnel.com",
]
for i, domain in enumerate(tunnel_domains):
    p = Ether() / IP(src="10.0.1.29", dst=DNS_SERVER) / \
        UDP(sport=58000, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
    p.time = ts(160 + i)
    packets.append(p)

# --- 12. Exfiltration (exfil.py) ---
# Large asymmetric outbound flow (>1MB out, minimal in)
exfil_data = b"E" * 1400
for i in range(1000):  # ~1.4MB outbound
    p = Ether() / IP(src="10.0.1.30", dst="192.0.2.50") / \
        TCP(sport=59000, dport=443, flags="PA") / Raw(load=exfil_data)
    p.time = ts(170 + i * 0.01)
    packets.append(p)
# Tiny inbound
for i in range(5):
    p = Ether() / IP(src="192.0.2.50", dst="10.0.1.30") / \
        TCP(sport=443, dport=59000, flags="A") / Raw(load=b"ack")
    p.time = ts(175 + i)
    packets.append(p)

# --- 13. Lateral Movement (lateral_movement.py) ---
# One source scanning SMB on 5+ internal targets
scanner = "10.0.1.40"
for i in range(7):
    target = f"10.0.1.{50 + i}"
    p = Ether() / IP(src=scanner, dst=target) / TCP(sport=60000, dport=445, flags="S")
    p.time = ts(185 + i * 0.5)
    packets.append(p)
    # SYN-ACK from some
    if i < 4:
        r = Ether() / IP(src=target, dst=scanner) / TCP(sport=445, dport=60000, flags="SA")
        r.time = ts(185.1 + i * 0.5)
        packets.append(r)

# RDP connections
p = Ether() / IP(src="10.0.1.40", dst="10.0.1.50") / TCP(sport=60001, dport=3389, flags="S")
p.time = ts(190)
packets.append(p)

# WinRM
p = Ether() / IP(src="10.0.1.40", dst="10.0.1.51") / TCP(sport=60002, dport=5985, flags="S")
p.time = ts(191)
packets.append(p)

# --- 14. NTLM (ntlm.py) ---
NTLMSSP_SIG = b"NTLMSSP\x00"
# Type 1 - Negotiate
ntlm_negotiate = NTLMSSP_SIG + struct.pack("<I", 1) + b"\x00" * 20
p = Ether() / IP(src="10.0.1.41", dst="10.0.1.50") / \
    TCP(sport=61000, dport=445, flags="PA") / Raw(load=ntlm_negotiate)
p.time = ts(195)
packets.append(p)

# Type 2 - Challenge
server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
ntlm_challenge = NTLMSSP_SIG + struct.pack("<I", 2) + b"\x00" * 12 + server_challenge + b"\x00" * 16
p = Ether() / IP(src="10.0.1.50", dst="10.0.1.41") / \
    TCP(sport=445, dport=61000, flags="PA") / Raw(load=ntlm_challenge)
p.time = ts(195.5)
packets.append(p)

# Type 3 - Authenticate
ntlm_auth = NTLMSSP_SIG + struct.pack("<I", 3) + b"\x00" * 40
p = Ether() / IP(src="10.0.1.41", dst="10.0.1.50") / \
    TCP(sport=61000, dport=445, flags="PA") / Raw(load=ntlm_auth)
p.time = ts(196)
packets.append(p)

# --- 15. PowerShell/WMI (powershell_wmi.py) ---
# WinRM with PS signatures
ps_payload = b"<rsp:Shell xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'>Microsoft.PowerShell</rsp:Shell>"
p = Ether() / IP(src="10.0.1.42", dst="10.0.1.50") / \
    TCP(sport=62000, dport=5985, flags="PA") / Raw(load=ps_payload)
p.time = ts(200)
packets.append(p)

# DCOM/WMI on port 135
dcom_payload = b"\x05\x00" + b"IWbemServices" + b"\x00" * 20
p = Ether() / IP(src="10.0.1.42", dst="10.0.1.51") / \
    TCP(sport=62001, dport=135, flags="PA") / Raw(load=dcom_payload)
p.time = ts(201)
packets.append(p)

# --- 16. Service Discovery (service_discovery.py) ---
# SYN-ACK responses from various service ports
services = [(22, "SSH"), (80, "HTTP"), (443, "HTTPS"), (3306, "MySQL"),
            (6379, "Redis"), (27017, "MongoDB"), (389, "LDAP")]
for i, (port, _) in enumerate(services):
    # SYN
    p = Ether() / IP(src="10.0.1.11", dst="10.0.1.30") / \
        TCP(sport=63000 + i, dport=port, flags="S")
    p.time = ts(210 + i)
    packets.append(p)
    # SYN-ACK
    r = Ether() / IP(src="10.0.1.30", dst="10.0.1.11") / \
        TCP(sport=port, dport=63000 + i, flags="SA")
    r.time = ts(210.1 + i)
    packets.append(r)

# --- 17. Suspicious User-Agents (suspicious_useragent.py) ---
agents = [
    "python-requests/2.28.0",
    "curl/7.88.1",
    "Nmap Scripting Engine",
    "sqlmap/1.7",
    "Go-http-client/1.1",
]
for i, ua in enumerate(agents):
    http_req = f"GET /api/data HTTP/1.1\r\nHost: 198.51.100.20\r\nUser-Agent: {ua}\r\n\r\n"
    p = Ether() / IP(src="10.0.1.43", dst="198.51.100.20") / \
        TCP(sport=64000 + i, dport=80, flags="PA") / Raw(load=http_req.encode())
    p.time = ts(220 + i)
    packets.append(p)

# --- 18. TLS Inspection (tls_inspect.py) ---
# TLS Alert - bad_certificate (42)
tls_alert = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 42])
p = Ether() / IP(src="198.51.100.20", dst="10.0.1.20") / \
    TCP(sport=443, dport=65000, flags="PA") / Raw(load=tls_alert)
p.time = ts(230)
packets.append(p)

# TLS Alert - unknown_ca (48)
tls_alert2 = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 48])
p = Ether() / IP(src="10.0.1.20", dst="198.51.100.20") / \
    TCP(sport=65001, dport=443, flags="PA") / Raw(load=tls_alert2)
p.time = ts(231)
packets.append(p)

# --- 19. Traffic Timeline (traffic_timeline.py) ---
# Traffic spike: burst of 50 packets in 0.5s
for i in range(50):
    p = Ether() / IP(src="10.0.1.11", dst="10.0.1.30") / \
        TCP(sport=40000, dport=80, flags="PA") / Raw(load=b"spike" * 10)
    p.time = ts(250 + i * 0.01)
    packets.append(p)

# Gap: no traffic for a few seconds (handled by surrounding traffic)

# Another burst
for i in range(30):
    p = Ether() / IP(src="10.0.1.12", dst="10.0.1.30") / \
        TCP(sport=40001, dport=80, flags="PA") / Raw(load=b"burst2" * 10)
    p.time = ts(260 + i * 0.01)
    packets.append(p)

# --- 20. VLAN Map (vlan_map.py) ---
# Dot1Q tagged packets on different VLANs
vlans = [10, 20, 30, 100]
for vlan in vlans:
    for i in range(5):
        src_ip = f"10.0.{vlan}.{10 + i}"
        dst_ip = f"10.0.{vlan}.{20 + i}"
        p = Ether() / Dot1Q(vlan=vlan) / IP(src=src_ip, dst=dst_ip) / \
            TCP(sport=44000, dport=80, flags="PA") / Raw(load=b"vlan traffic")
        p.time = ts(270 + vlan + i * 0.1)
        packets.append(p)

# Cross-VLAN traffic
p = Ether() / Dot1Q(vlan=10) / IP(src="10.0.10.10", dst="10.0.20.10") / \
    TCP(sport=44100, dport=443, flags="PA") / Raw(load=b"cross-vlan")
p.time = ts(275)
packets.append(p)
p = Ether() / Dot1Q(vlan=20) / IP(src="10.0.20.10", dst="10.0.30.10") / \
    TCP(sport=44101, dport=445, flags="PA") / Raw(load=b"cross-vlan-smb")
p.time = ts(276)
packets.append(p)

# --- Sort all packets by time and write ---
packets.sort(key=lambda p: float(p.time))
output_path = "/Users/andylombardo/Projects/pcap-bloodhound/ephemeral/dummy_traffic.pcap"
wrpcap(output_path, packets)
print(f"Written {len(packets)} packets to {output_path}")
