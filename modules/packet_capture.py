"""
Packet Capture Module for Phishing Detection System

This module handles:
- Real-time packet sniffing from network interfaces
- DNS packet extraction
- TLS/SSL handshake packet extraction
- Raw packet data collection for feature engineering

Author: Research Team
Date: 2026
"""

import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import threading
import queue

from scapy.all import (
    sniff, IP, IPv6, DNS, DNSQR, Raw,
    TCP, UDP, ICMP, get_if_list, conf
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DNSPacketData:
    """Data class for DNS packet information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    query_domain: str
    query_type: str
    ttl: int
    packet_size: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)


@dataclass
class TLSPacketData:
    """Data class for TLS/SSL handshake information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sni: Optional[str]  # Server Name Indication
    tls_version: Optional[str]
    cipher_suites: Optional[List[str]]
    packet_size: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)


@dataclass
class TrafficFlowData:
    """Data class for traffic flow features"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    ttl: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)


class DNSExtractor:
    """Extracts DNS query information from packets"""
    
    @staticmethod
    def extract(packet) -> Optional[DNSPacketData]:
        """
        Extract DNS information from a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            DNSPacketData object or None if not a DNS packet
        """
        try:
            if not packet.haslayer(DNS):
                return None
            
            dns_layer = packet[DNS]
            
            # Only process DNS queries (not responses)
            if dns_layer.qr != 0:  # qr=0 means query
                return None
            
            # Extract query information
            if not dns_layer.qd:
                return None
            
            query = dns_layer.qd[0]
            domain = query.qname.decode('utf-8').rstrip('.')
            query_type = DNSExtractor._get_query_type(query.qtype)
            
            # Get IP information
            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
            ttl = packet[IP].ttl if packet.haslayer(IP) else 0
            
            return DNSPacketData(
                timestamp=datetime.now().timestamp(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                query_domain=domain,
                query_type=query_type,
                ttl=ttl,
                packet_size=len(packet)
            )
            
        except Exception as e:
            logger.debug(f"Error extracting DNS packet: {e}")
            return None
    
    @staticmethod
    def _get_query_type(qtype: int) -> str:
        """Map DNS query type number to string"""
        query_types = {
            1: "A",      # IPv4 address
            28: "AAAA",  # IPv6 address
            5: "CNAME",  # Canonical name
            15: "MX",    # Mail exchange
            16: "TXT",   # Text record
            2: "NS",     # Nameserver
        }
        return query_types.get(qtype, f"TYPE_{qtype}")


class TLSExtractor:
    """Extracts TLS/SSL handshake information from packets"""
    
    @staticmethod
    def extract(packet) -> Optional[TLSPacketData]:
        """
        Extract TLS handshake information from a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            TLSPacketData object or None if not a TLS packet
        """
        try:
            if not packet.haslayer(TCP):
                return None
            
            # Check for TLS/SSL traffic (typical ports)
            tcp_layer = packet[TCP]
            dst_port = tcp_layer.dport
            src_port = tcp_layer.sport
            
            # TLS typically on 443, but also check for Client Hello
            sni = TLSExtractor._extract_sni(packet)
            
            if sni is None and dst_port not in [443, 8443]:
                return None
            
            # Get IP information
            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
            ttl = packet[IP].ttl if packet.haslayer(IP) else 0
            
            return TLSPacketData(
                timestamp=datetime.now().timestamp(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                sni=sni,
                tls_version=TLSExtractor._extract_tls_version(packet),
                cipher_suites=TLSExtractor._extract_cipher_suites(packet),
                packet_size=len(packet)
            )
            
        except Exception as e:
            logger.debug(f"Error extracting TLS packet: {e}")
            return None
    
    @staticmethod
    def _extract_sni(packet) -> Optional[str]:
        """
        Extract Server Name Indication (SNI) from TLS Client Hello
        
        SNI is crucial for phishing detection as it reveals the intended domain
        before certificate validation occurs.
        """
        try:
            if not packet.haslayer(Raw):
                return None
            
            raw_load = packet[Raw].load
            
            # TLS record starts at byte 0, look for Client Hello
            # Structure: [content_type(1)] [version(2)] [length(2)] [handshake_type(1)]
            if len(raw_load) < 43:
                return None
            
            # Check if it's a Client Hello (handshake_type = 1)
            if raw_load[5] != 0x01:
                return None
            
            # Parse SNI extension (type 0x00)
            # This is a simplified parser; full TLS parsing would use pyshark
            sni = TLSExtractor._parse_sni_from_client_hello(raw_load)
            return sni
            
        except Exception as e:
            logger.debug(f"Error extracting SNI: {e}")
            return None
    
    @staticmethod
    def _parse_sni_from_client_hello(data: bytes) -> Optional[str]:
        """
        Parse SNI from TLS Client Hello payload
        
        SNI format in Client Hello:
        - Extension type: 0x00, 0x00 (2 bytes)
        - Extension length (2 bytes)
        - List length (2 bytes)
        - Entry type 0x00 (1 byte) - host_name
        - Name length (2 bytes)
        - Name (variable)
        """
        try:
            # Start after fixed ClientHello fields (roughly at byte 43)
            offset = 43
            
            while offset < len(data) - 5:
                # Check for SNI extension type (0x0000)
                if data[offset:offset+2] == b'\x00\x00':
                    # Read extension length
                    ext_len = int.from_bytes(data[offset+2:offset+4], 'big')
                    
                    # SNI list length
                    list_len = int.from_bytes(data[offset+4:offset+6], 'big')
                    
                    # Skip list type and get name length
                    if offset + 9 < len(data):
                        name_len = int.from_bytes(data[offset+7:offset+9], 'big')
                        
                        # Extract domain name
                        if offset + 9 + name_len <= len(data):
                            sni = data[offset+9:offset+9+name_len].decode('utf-8', errors='ignore')
                            return sni
                
                offset += 1
            
            return None
            
        except Exception as e:
            logger.debug(f"Error parsing SNI: {e}")
            return None
    
    @staticmethod
    def _extract_tls_version(packet) -> Optional[str]:
        """Extract TLS version from packet"""
        try:
            if not packet.haslayer(Raw):
                return None
            
            raw_load = packet[Raw].load
            if len(raw_load) >= 2:
                major, minor = raw_load[0], raw_load[1]
                
                versions = {
                    (3, 1): "TLS 1.0",
                    (3, 2): "TLS 1.1",
                    (3, 3): "TLS 1.2",
                    (3, 4): "TLS 1.3",
                }
                return versions.get((major, minor), f"Unknown_{major}.{minor}")
            
            return None
            
        except Exception as e:
            logger.debug(f"Error extracting TLS version: {e}")
            return None
    
    @staticmethod
    def _extract_cipher_suites(packet) -> Optional[List[str]]:
        """Extract cipher suites from Client Hello"""
        # Simplified - full implementation would parse all ciphers
        try:
            if not packet.haslayer(Raw):
                return None
            # This would require detailed TLS parsing
            # For now, return placeholder
            return None
        except:
            return None


class TrafficFlowExtractor:
    """Extracts general traffic flow features"""
    
    @staticmethod
    def extract(packet) -> Optional[TrafficFlowData]:
        """
        Extract traffic flow information from a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            TrafficFlowData object or None
        """
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            
            # Determine protocol
            protocol = "Unknown"
            src_port = 0
            dst_port = 0
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            
            return TrafficFlowData(
                timestamp=datetime.now().timestamp(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=len(packet),
                ttl=ttl
            )
            
        except Exception as e:
            logger.debug(f"Error extracting traffic flow: {e}")
            return None


class RealTimePacketSniffer:
    """
    Real-time packet sniffer with threaded processing
    
    Captures packets and processes them with callbacks while
    maintaining separation between capture and processing.
    """
    
    def __init__(self, interface: Optional[str] = None, packet_count: int = 0):
        """
        Initialize packet sniffer
        
        Args:
            interface: Network interface to sniff on (None = default)
            packet_count: Number of packets to capture (0 = infinite)
        """
        self.interface = interface or conf.iface
        self.packet_count = packet_count
        self.is_running = False
        self.packet_queue = queue.Queue()
        self.callbacks: Dict[str, List[Callable]] = {
            'dns': [],
            'tls': [],
            'flow': []
        }
        self.sniffer_thread = None
        self.stats = {
            'packets_captured': 0,
            'dns_packets': 0,
            'tls_packets': 0,
            'flow_packets': 0
        }
        
        logger.info(f"Initialized packet sniffer on interface: {self.interface}")
    
    def register_callback(self, packet_type: str, callback: Callable) -> None:
        """
        Register a callback for specific packet types
        
        Args:
            packet_type: 'dns', 'tls', or 'flow'
            callback: Function to call with extracted packet data
        """
        if packet_type not in self.callbacks:
            raise ValueError(f"Unknown packet type: {packet_type}")
        
        self.callbacks[packet_type].append(callback)
        logger.info(f"Registered callback for {packet_type} packets")
    
    def _process_packet(self, packet) -> None:
        """
        Internal packet processing callback for Scapy
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.stats['packets_captured'] += 1
            
            # Try DNS extraction
            dns_data = DNSExtractor.extract(packet)
            if dns_data:
                self.stats['dns_packets'] += 1
                for callback in self.callbacks['dns']:
                    try:
                        callback(dns_data)
                    except Exception as e:
                        logger.error(f"DNS callback error: {e}")
            
            # Try TLS extraction
            tls_data = TLSExtractor.extract(packet)
            if tls_data:
                self.stats['tls_packets'] += 1
                for callback in self.callbacks['tls']:
                    try:
                        callback(tls_data)
                    except Exception as e:
                        logger.error(f"TLS callback error: {e}")
            
            # Extract general traffic flow
            flow_data = TrafficFlowExtractor.extract(packet)
            if flow_data:
                self.stats['flow_packets'] += 1
                for callback in self.callbacks['flow']:
                    try:
                        callback(flow_data)
                    except Exception as e:
                        logger.error(f"Flow callback error: {e}")
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start(self) -> None:
        """Start packet sniffing in background thread"""
        if self.is_running:
            logger.warning("Sniffer already running")
            return
        
        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        logger.info("Packet sniffer started")
    
    def _sniff_packets(self) -> None:
        """Internal method to run Scapy sniffer"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                count=self.packet_count,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
        finally:
            self.is_running = False
            logger.info("Packet sniffer stopped")
    
    def stop(self) -> None:
        """Stop packet sniffing"""
        self.is_running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        logger.info("Packet sniffer shutdown")
    
    def get_stats(self) -> Dict:
        """Get sniffer statistics"""
        return self.stats.copy()
    
    def print_stats(self) -> None:
        """Print sniffer statistics"""
        print("\n" + "="*50)
        print("PACKET SNIFFER STATISTICS")
        print("="*50)
        for key, value in self.stats.items():
            print(f"{key}: {value}")
        print("="*50 + "\n")


class PacketCaptureConfig:
    """Configuration class for packet capture"""
    
    # Network interfaces
    AVAILABLE_INTERFACES = get_if_list()
    DEFAULT_INTERFACE = conf.iface
    
    # Packet capture filters
    DNS_FILTER = "udp port 53"
    TLS_FILTER = "tcp port 443 or tcp port 8443"
    ALL_FILTER = "tcp or udp or icmp"
    
    # Capture settings
    PACKET_COUNT = 0  # 0 = unlimited
    SNAPLEN = 65535   # Maximum bytes per packet
    TIMEOUT = 0       # No timeout
