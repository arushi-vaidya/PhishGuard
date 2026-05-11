#!/usr/bin/env python3
"""
Debug: Find Chrome Traffic - See What Interface & Packets Scapy Actually Captures

Run: sudo python3 debug_chrome_traffic.py
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf
import sys
from datetime import datetime
from collections import defaultdict

print("\n" + "="*80)
print("🔍 CHROME TRAFFIC DEBUGGER")
print("="*80)

print("\n📋 Step 1: Check Available Interfaces")
print("-" * 80)

try:
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print(f"Found {len(interfaces)} interfaces:")
    for iface in interfaces:
        print(f"  • {iface}")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

# Ask user which interface to use
print("\n⚡ Using: en0 (most common)")
interface = "en0"

print(f"\n📋 Step 2: Start Packet Capture on {interface}")
print("-" * 80)
print(f"Capturing for 30 seconds...")
print(f"Now OPEN CHROME and visit: http://google.com\n")

packet_count = 0
dns_queries = defaultdict(int)
tls_domains = []
http_hosts = []

def packet_callback(pkt):
    """Capture and analyze packets"""
    global packet_count, dns_queries, tls_domains, http_hosts
    packet_count += 1
    
    # Check for DNS
    if DNS in pkt:
        if DNSQR in pkt:
            domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
            if domain:
                dns_queries[domain] += 1
                print(f"  🔹 DNS Query #{packet_count}: {domain}")
    
    # Check for TLS/SNI (in Client Hello)
    if TCP in pkt:
        raw = bytes(pkt[TCP].payload)
        # Look for TLS handshake
        if len(raw) > 43 and raw[0:2] == b'\x16\x03':  # TLS handshake
            # Look for SNI in Client Hello
            try:
                idx = raw.find(b'\x00\x00')  # SNI extension marker
                if idx > 0 and idx < len(raw) - 10:
                    sni_len = int.from_bytes(raw[idx+2:idx+4], 'big')
                    if sni_len > 0 and sni_len < 300:
                        sni = raw[idx+9:idx+9+sni_len].decode('utf-8', errors='ignore')
                        if '.' in sni and len(sni) > 3:
                            tls_domains.append(sni)
                            print(f"  🟦 TLS SNI #{packet_count}: {sni}")
            except:
                pass
    
    # Check for HTTP Host header
    if TCP in pkt:
        raw = bytes(pkt[TCP].payload)
        if b'Host: ' in raw:
            try:
                host_idx = raw.find(b'Host: ')
                host_end = raw.find(b'\r\n', host_idx)
                if host_end > host_idx:
                    host = raw[host_idx+6:host_end].decode('utf-8', errors='ignore')
                    if host and host not in http_hosts:
                        http_hosts.append(host)
                        print(f"  🟥 HTTP Host #{packet_count}: {host}")
            except:
                pass

try:
    # Start capturing
    sniff(iface=interface, prn=packet_callback, timeout=30, store=False)
except PermissionError:
    print("\n❌ ERROR: Need sudo to capture packets!")
    print("Run: sudo python3 debug_chrome_traffic.py")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    sys.exit(1)

# Print summary
print("\n" + "="*80)
print("📊 CAPTURE SUMMARY")
print("="*80)

print(f"\nTotal Packets Captured: {packet_count}")

if dns_queries:
    print(f"\n🔹 DNS Queries Found ({len(dns_queries)}):")
    for domain, count in sorted(dns_queries.items(), key=lambda x: -x[1])[:10]:
        print(f"  {domain:40} ({count}x)")
else:
    print("\n❌ No DNS queries captured - Chrome might be using DNS-over-HTTPS (DoH)")

if tls_domains:
    print(f"\n🟦 TLS SNI Domains Found ({len(set(tls_domains))}):")
    for domain in sorted(set(tls_domains))[:10]:
        print(f"  {domain}")
else:
    print("\n❌ No TLS SNI captured - Scapy can't read encrypted packets on macOS")

if http_hosts:
    print(f"\n🟥 HTTP Host Headers Found ({len(http_hosts)}):")
    for host in http_hosts[:10]:
        print(f"  {host}")
else:
    print("\n❌ No HTTP hosts found - Chrome uses HTTPS")

print("\n" + "="*80)
print("🔧 TROUBLESHOOTING")
print("="*80)

if packet_count < 100:
    print("""
⚠️  Very few packets captured. This could mean:

1. macOS restrictions on Scapy
   → Try: sudo tcpdump -i en0 -n 'port 53 or (tcp port 443 and tcp[((tcp[12:1]&0xf0)>>2):1] == 0x16)'

2. Chrome using DNS-over-HTTPS (DoH)
   → Open Chrome → Settings → Privacy → DNS over HTTPS → Disable it
   → Then try again

3. Wrong interface
   → Try: en1, en2, bridge0, etc.
   → Check: ifconfig | grep "inet " (to see which has traffic)

4. VPN/proxy interfering
   → Disconnect VPN
   → Check proxy settings

5. macOS Sonoma/Ventura sandboxing
   → Scapy has limited access on recent macOS
   → Try: networksetup -listallnetworkservices
""")
else:
    print("""
✅ Good! Scapy is capturing packets.

If no domains showing up:
- Chrome is using HTTPS (encrypted)
- Try opening unencrypted sites or check Chrome DNS settings
""")

print("="*80 + "\n")
