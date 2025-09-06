import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from scapy.all import Packet, IP, TCP, UDP, ICMP, DNS, ARP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS
import struct
import base64

from utils.logger import setup_logger

logger = setup_logger(__name__)

class PacketAnalyzer:
    def __init__(self):
        self.suspicious_domains = self._load_suspicious_domains()
        self.iot_protocols = self._load_iot_protocols()
        
    def _load_suspicious_domains(self) -> List[str]:
        """Load known malicious/suspicious domain list"""
        return [
            "malware.com", "phishing.net", "botnet.org",
            "c2server.net", "suspicious.domain"
        ]
    
    def _load_iot_protocols(self) -> Dict[int, str]:
        """Load IoT protocol port mappings"""
        return {
            1883: "MQTT",
            8883: "MQTT-SSL",
            5683: "CoAP",
            5684: "CoAP-SSL", 
            502: "Modbus",
            20000: "DNP3",
            47808: "BACnet",
            161: "SNMP",
            162: "SNMP-Trap",
            69: "TFTP",
            67: "DHCP",
            68: "DHCP",
            123: "NTP",
            1900: "UPnP-SSDP"
        }
    
    def analyze_packet(self, packet: Packet) -> Dict[str, Any]:
        """Comprehensive packet analysis"""
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "basic_info": self._extract_basic_info(packet),
            "protocol_analysis": self._analyze_protocols(packet),
            "content_analysis": self._analyze_content(packet),
            "security_analysis": self._security_analysis(packet),
            "iot_analysis": self._iot_analysis(packet),
            "anomaly_scores": self._calculate_anomaly_scores(packet)
        }
        
        return analysis
    
    def _extract_basic_info(self, packet: Packet) -> Dict[str, Any]:
        """Extract basic packet information"""
        info = {
            "packet_size": len(packet),
            "protocols": []
        }
        
        if packet.haslayer(IP):
            ip = packet[IP]
            info.update({
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": ip.ttl,
                "protocol": ip.proto,
                "fragment_offset": ip.frag,
                "ip_version": ip.version
            })
            info["protocols"].append("IP")
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info.update({
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "tcp_flags": tcp.flags,
                "tcp_window": tcp.window,
                "tcp_seq": tcp.seq,
                "tcp_ack": tcp.ack
            })
            info["protocols"].append("TCP")
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info.update({
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "udp_length": udp.len
            })
            info["protocols"].append("UDP")
        
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info.update({
                "icmp_type": icmp.type,
                "icmp_code": icmp.code
            })
            info["protocols"].append("ICMP")
        
        return info
    
    def _analyze_protocols(self, packet: Packet) -> Dict[str, Any]:
        """Analyze application layer protocols"""
        protocols = {}
        
        if packet.haslayer(DNS):
            protocols["dns"] = self._analyze_dns(packet[DNS])
        
        if packet.haslayer(HTTPRequest):
            protocols["http_request"] = self._analyze_http_request(packet)
            
        if packet.haslayer(HTTPResponse):
            protocols["http_response"] = self._analyze_http_response(packet)
        
        if packet.haslayer(TLS):
            protocols["tls"] = self._analyze_tls(packet[TLS])
        
        if packet.haslayer(ARP):
            protocols["arp"] = self._analyze_arp(packet[ARP])
        
        protocols["iot_protocol"] = self._detect_iot_protocol(packet)
        
        return protocols
    
    def _analyze_dns(self, dns) -> Dict[str, Any]:
        """Analyze DNS packet"""
        analysis = {
            "query_type": dns.opcode,
            "response_code": dns.rcode if hasattr(dns, 'rcode') else None,
            "queries": [],
            "answers": []
        }
        
        if hasattr(dns, 'qd') and dns.qd:
            query = dns.qd
            analysis["queries"].append({
                "name": str(query.qname, 'utf-8').rstrip('.') if isinstance(query.qname, bytes) else str(query.qname).rstrip('.'),
                "type": query.qtype,
                "class": query.qclass
            })
        
        if hasattr(dns, 'an') and dns.an:
            for i in range(dns.ancount):
                answer = dns.an[i] if isinstance(dns.an, list) else dns.an
                analysis["answers"].append({
                    "name": str(answer.rrname).rstrip('.'),
                    "type": answer.type,
                    "data": str(answer.rdata)
                })
        
        return analysis
    
    def _analyze_http_request(self, packet) -> Dict[str, Any]:
        """Analyze HTTP request"""
        http = packet[HTTPRequest]
        
        analysis = {
            "method": http.Method.decode() if http.Method else "Unknown",
            "host": http.Host.decode() if http.Host else "Unknown",
            "path": http.Path.decode() if http.Path else "/",
            "user_agent": http.User_Agent.decode() if http.User_Agent else None,
            "headers": {}
        }
        
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if raw_data:
                try:
                    headers_str = raw_data.decode('utf-8', errors='ignore')
                    analysis["raw_headers"] = headers_str
                except:
                    pass
        
        return analysis
    
    def _analyze_http_response(self, packet) -> Dict[str, Any]:
        """Analyze HTTP response"""
        http = packet[HTTPResponse]
        
        analysis = {
            "status_code": http.Status_Code.decode() if http.Status_Code else "Unknown",
            "server": http.Server.decode() if http.Server else None,
            "content_type": http.Content_Type.decode() if http.Content_Type else None,
            "content_length": http.Content_Length.decode() if http.Content_Length else None
        }
        
        return analysis
    
    def _analyze_tls(self, tls) -> Dict[str, Any]:
        """Analyze TLS packet"""
        analysis = {
            "version": getattr(tls, 'version', None),
            "content_type": getattr(tls, 'type', None),
            "cipher_suite": None,
            "server_name": None
        }
        
        return analysis
    
    def _analyze_arp(self, arp) -> Dict[str, Any]:
        """Analyze ARP packet"""
        return {
            "operation": arp.op,
            "sender_mac": arp.hwsrc,
            "sender_ip": arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst
        }
    
    def _detect_iot_protocol(self, packet) -> Optional[Dict[str, Any]]:
        """Detect IoT-specific protocols"""
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return None
        
        port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
        
        protocol = self.iot_protocols.get(port) or self.iot_protocols.get(src_port)
        
        if protocol:
            analysis = {
                "protocol": protocol,
                "port": port,
                "payload_analysis": None
            }
            
            if protocol == "MQTT":
                analysis["payload_analysis"] = self._analyze_mqtt(packet)
            elif protocol == "CoAP":
                analysis["payload_analysis"] = self._analyze_coap(packet)
            elif protocol == "Modbus":
                analysis["payload_analysis"] = self._analyze_modbus(packet)
            
            return analysis
        
        return None
    
    def _analyze_mqtt(self, packet) -> Dict[str, Any]:
        """Analyze MQTT payload"""
        if not packet.haslayer(Raw):
            return {}
        
        try:
            payload = packet[Raw].load
            if len(payload) < 2:
                return {}
            
            # MQTT fixed header analysis
            message_type = (payload[0] >> 4) & 0x0F
            flags = payload[0] & 0x0F
            
            mqtt_types = {
                1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
                5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
                9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ",
                13: "PINGRESP", 14: "DISCONNECT"
            }
            
            return {
                "message_type": mqtt_types.get(message_type, "Unknown"),
                "flags": flags,
                "payload_length": len(payload)
            }
        except Exception as e:
            logger.debug(f"MQTT analysis error: {e}")
            return {}
    
    def _analyze_coap(self, packet) -> Dict[str, Any]:
        """Analyze CoAP payload"""
        if not packet.haslayer(Raw):
            return {}
        
        try:
            payload = packet[Raw].load
            if len(payload) < 4:
                return {}
            
            version = (payload[0] >> 6) & 0x03
            message_type = (payload[0] >> 4) & 0x03
            token_length = payload[0] & 0x0F
            code = payload[1]
            
            coap_types = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
            
            return {
                "version": version,
                "type": coap_types.get(message_type, "Unknown"),
                "token_length": token_length,
                "code": code
            }
        except Exception as e:
            logger.debug(f"CoAP analysis error: {e}")
            return {}
    
    def _analyze_modbus(self, packet) -> Dict[str, Any]:
        """Analyze Modbus payload"""
        if not packet.haslayer(Raw):
            return {}
        
        try:
            payload = packet[Raw].load
            if len(payload) < 6:
                return {}
            
            if packet.haslayer(TCP):
                # Modbus TCP
                transaction_id = struct.unpack(">H", payload[0:2])[0]
                protocol_id = struct.unpack(">H", payload[2:4])[0]
                length = struct.unpack(">H", payload[4:6])[0]
                unit_id = payload[6]
                function_code = payload[7] if len(payload) > 7 else None
                
                return {
                    "transaction_id": transaction_id,
                    "protocol_id": protocol_id,
                    "length": length,
                    "unit_id": unit_id,
                    "function_code": function_code
                }
        except Exception as e:
            logger.debug(f"Modbus analysis error: {e}")
            return {}
    
    def _analyze_content(self, packet) -> Dict[str, Any]:
        """Analyze packet content for suspicious patterns"""
        analysis = {
            "has_payload": packet.haslayer(Raw),
            "payload_size": len(packet[Raw].load) if packet.haslayer(Raw) else 0,
            "suspicious_strings": [],
            "binary_analysis": {},
            "encoding_detection": None
        }
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            
            # Look for suspicious strings
            suspicious_patterns = [
                b"exec", b"system", b"shell", b"/bin/", b"cmd.exe",
                b"powershell", b"wget", b"curl", b"nc ", b"netcat",
                b"password", b"passwd", b"admin", b"root",
                b"backdoor", b"malware", b"trojan"
            ]
            
            for pattern in suspicious_patterns:
                if pattern in payload:
                    analysis["suspicious_strings"].append(pattern.decode('utf-8', errors='ignore'))
            
            # Binary analysis
            analysis["binary_analysis"] = {
                "entropy": self._calculate_entropy(payload),
                "printable_ratio": self._calculate_printable_ratio(payload),
                "null_bytes": payload.count(b'\x00'),
                "high_entropy_segments": self._find_high_entropy_segments(payload)
            }
        
        return analysis
    
    def _security_analysis(self, packet) -> Dict[str, Any]:
        """Perform security-focused analysis"""
        analysis = {
            "is_encrypted": False,
            "potential_threats": [],
            "suspicious_indicators": [],
            "attack_patterns": []
        }
        
        # Check for encryption indicators
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport in [443, 993, 995, 22, 636] or tcp.sport in [443, 993, 995, 22, 636]:
                analysis["is_encrypted"] = True
        
        # Check for potential DDoS patterns
        if packet.haslayer(IP):
            ip = packet[IP]
            if ip.ttl < 30 or ip.ttl > 250:
                analysis["suspicious_indicators"].append("Unusual TTL value")
            
            if ip.flags & 0x2:  # Don't Fragment flag
                analysis["suspicious_indicators"].append("DF flag set")
        
        # Check for port scanning patterns
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags & 0x02 and not tcp.flags & 0x10:  # SYN without ACK
                if tcp.dport in range(1, 1024):
                    analysis["attack_patterns"].append("Potential port scan")
        
        # Check for suspicious DNS queries
        if packet.haslayer(DNS) and hasattr(packet[DNS], 'qd') and packet[DNS].qd:
            query_name = str(packet[DNS].qd.qname, 'utf-8').rstrip('.') if isinstance(packet[DNS].qd.qname, bytes) else str(packet[DNS].qd.qname).rstrip('.')
            
            if any(domain in query_name for domain in self.suspicious_domains):
                analysis["potential_threats"].append(f"Suspicious domain query: {query_name}")
            
            if len(query_name) > 100 or query_name.count('.') > 10:
                analysis["suspicious_indicators"].append("Unusual DNS query structure")
        
        return analysis
    
    def _iot_analysis(self, packet) -> Dict[str, Any]:
        """IoT-specific analysis"""
        analysis = {
            "is_iot_traffic": False,
            "device_behavior": [],
            "protocol_violations": [],
            "unusual_patterns": []
        }
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            
            if port in self.iot_protocols or src_port in self.iot_protocols:
                analysis["is_iot_traffic"] = True
        
        # Check for common IoT device behaviors
        if packet.haslayer(IP):
            ip = packet[IP]
            
            # Check for local network communication
            src_local = self._is_local_ip(ip.src)
            dst_local = self._is_local_ip(ip.dst)
            
            if src_local and not dst_local:
                analysis["device_behavior"].append("Outbound internet communication")
            elif not src_local and dst_local:
                analysis["device_behavior"].append("Inbound internet communication")
            elif src_local and dst_local:
                analysis["device_behavior"].append("Local network communication")
        
        return analysis
    
    def _calculate_anomaly_scores(self, packet) -> Dict[str, float]:
        """Calculate various anomaly scores"""
        scores = {
            "size_anomaly": 0.0,
            "protocol_anomaly": 0.0,
            "timing_anomaly": 0.0,
            "content_anomaly": 0.0,
            "overall_score": 0.0
        }
        
        # Size anomaly
        packet_size = len(packet)
        if packet_size > 1500 or packet_size < 64:
            scores["size_anomaly"] = min(1.0, abs(packet_size - 800) / 1000)
        
        # Protocol anomaly
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport > 49152 or tcp.sport > 49152:  # Ephemeral ports
                scores["protocol_anomaly"] += 0.2
        
        # Content anomaly
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            entropy = self._calculate_entropy(payload)
            if entropy > 7.5:  # High entropy might indicate encryption or compression
                scores["content_anomaly"] = (entropy - 7.5) / 0.5
        
        # Calculate overall score
        scores["overall_score"] = (
            scores["size_anomaly"] * 0.2 +
            scores["protocol_anomaly"] * 0.3 +
            scores["timing_anomaly"] * 0.2 +
            scores["content_anomaly"] * 0.3
        )
        
        return scores
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for i in range(256):
            p = data.count(i) / len(data)
            if p > 0:
                entropy -= p * (p).bit_length()
        
        return entropy
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable characters"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)
    
    def _find_high_entropy_segments(self, data: bytes, window_size: int = 32) -> List[Dict]:
        """Find segments with high entropy"""
        high_entropy_segments = []
        
        for i in range(0, len(data) - window_size, window_size):
            segment = data[i:i + window_size]
            entropy = self._calculate_entropy(segment)
            
            if entropy > 7.0:
                high_entropy_segments.append({
                    "offset": i,
                    "entropy": entropy,
                    "length": len(segment)
                })
        
        return high_entropy_segments
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is in local network ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False