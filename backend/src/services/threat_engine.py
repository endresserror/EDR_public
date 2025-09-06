import asyncio
import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from scapy.all import Packet

from models.alert import Alert, AlertSeverity, AlertStatus
from models.threat_rule import ThreatRule, ThreatRuleType
from models.device import Device
from services.packet_analyzer import PacketAnalyzer
from utils.logger import setup_logger

logger = setup_logger(__name__)

class ThreatEngine:
    def __init__(self):
        self.packet_analyzer = PacketAnalyzer()
        self.rules: List[ThreatRule] = []
        self.detection_cache = {}
        self.baseline_metrics = {}
        
    async def load_rules(self):
        """Load threat detection rules"""
        self.rules = []
        
        # Default IoT threat detection rules (20 patterns)
        default_rules = [
            {
                "name": "Suspicious Outbound Connection",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "outbound_connection",
                    "conditions": {
                        "destination_ports": [22, 23, 1433, 3306, 5432],
                        "protocols": ["TCP"],
                        "external_only": True
                    }
                }),
                "severity": "high",
                "description": "IoT device connecting to suspicious external ports"
            },
            {
                "name": "High Volume Data Transfer",
                "rule_type": ThreatRuleType.ANOMALY,
                "rule_content": json.dumps({
                    "type": "data_volume",
                    "conditions": {
                        "threshold_mbps": 10,
                        "duration_minutes": 5,
                        "device_types": ["camera", "sensor", "smart_plug"]
                    }
                }),
                "severity": "medium",
                "description": "Unusual high volume data transfer from IoT device"
            },
            {
                "name": "DNS Tunneling Detection",
                "rule_type": ThreatRuleType.SIGNATURE,
                "rule_content": json.dumps({
                    "type": "dns_anomaly",
                    "conditions": {
                        "query_length_threshold": 100,
                        "subdomain_count_threshold": 10,
                        "entropy_threshold": 4.0
                    }
                }),
                "severity": "high",
                "description": "Potential DNS tunneling activity detected"
            },
            {
                "name": "Botnet Communication Pattern",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "botnet_communication",
                    "conditions": {
                        "periodic_connection": True,
                        "interval_seconds": [300, 600, 900],
                        "external_ips": True,
                        "encrypted": False
                    }
                }),
                "severity": "critical",
                "description": "Potential botnet communication detected"
            },
            {
                "name": "Unauthorized Protocol Usage",
                "rule_type": ThreatRuleType.SIGNATURE,
                "rule_content": json.dumps({
                    "type": "protocol_violation",
                    "conditions": {
                        "unexpected_protocols": ["SSH", "Telnet", "FTP"],
                        "device_types": ["camera", "sensor", "smart_bulb"]
                    }
                }),
                "severity": "medium",
                "description": "IoT device using unexpected protocol"
            },
            {
                "name": "Brute Force Attack",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "brute_force",
                    "conditions": {
                        "failed_attempts_threshold": 10,
                        "time_window_minutes": 10,
                        "protocols": ["SSH", "Telnet", "HTTP"],
                        "target_ports": [22, 23, 80, 8080]
                    }
                }),
                "severity": "high",
                "description": "Brute force attack attempt detected"
            },
            {
                "name": "Malware C2 Communication",
                "rule_type": ThreatRuleType.REPUTATION,
                "rule_content": json.dumps({
                    "type": "malicious_ip",
                    "conditions": {
                        "check_reputation": True,
                        "blacklist_sources": ["abuse.ch", "malwaredomains.com"],
                        "connection_patterns": ["periodic", "heartbeat"]
                    }
                }),
                "severity": "critical",
                "description": "Communication with known malicious IP detected"
            },
            {
                "name": "IoT Device Scanning",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "port_scan",
                    "conditions": {
                        "port_range_scan": True,
                        "connection_attempts_threshold": 20,
                        "time_window_seconds": 60,
                        "tcp_syn_only": True
                    }
                }),
                "severity": "medium",
                "description": "IoT device performing network scanning"
            },
            {
                "name": "Unusual Night Time Activity",
                "rule_type": ThreatRuleType.ANOMALY,
                "rule_content": json.dumps({
                    "type": "time_based_anomaly",
                    "conditions": {
                        "time_range": {"start": "22:00", "end": "06:00"},
                        "activity_threshold_multiplier": 5.0,
                        "device_types": ["smart_tv", "smart_speaker"]
                    }
                }),
                "severity": "low",
                "description": "Unusual activity during night hours"
            },
            {
                "name": "Cryptocurrency Mining Detection",
                "rule_type": ThreatRuleType.SIGNATURE,
                "rule_content": json.dumps({
                    "type": "crypto_mining",
                    "conditions": {
                        "mining_pool_domains": [".*\\.pool\\..*", ".*mining.*", ".*stratum.*"],
                        "mining_ports": [4444, 8080, 3333, 9999],
                        "cpu_usage_pattern": "high_sustained"
                    }
                }),
                "severity": "high",
                "description": "Potential cryptocurrency mining activity"
            },
            {
                "name": "DDoS Attack Detection",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "ddos_attack",
                    "conditions": {
                        "packet_rate_threshold": 1000,
                        "time_window_seconds": 60,
                        "target_diversity": False,
                        "protocol_types": ["TCP", "UDP", "ICMP"]
                    }
                }),
                "severity": "critical",
                "description": "Distributed Denial of Service attack pattern"
            },
            {
                "name": "Lateral Movement Detection",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "lateral_movement",
                    "conditions": {
                        "internal_scan_ports": [135, 139, 445, 3389, 5985],
                        "rapid_connection_attempts": True,
                        "credential_reuse_pattern": True,
                        "time_window_minutes": 30
                    }
                }),
                "severity": "high",
                "description": "Lateral movement within network"
            },
            {
                "name": "Data Exfiltration Detection",
                "rule_type": ThreatRuleType.ANOMALY,
                "rule_content": json.dumps({
                    "type": "data_exfiltration",
                    "conditions": {
                        "upload_volume_threshold_mb": 100,
                        "time_window_hours": 1,
                        "external_destinations": True,
                        "unusual_times": ["22:00-06:00"]
                    }
                }),
                "severity": "critical",
                "description": "Suspicious large data uploads"
            },
            {
                "name": "Command and Control Beaconing",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "c2_beaconing",
                    "conditions": {
                        "regular_intervals": [60, 300, 600, 1800],
                        "consistent_payload_size": True,
                        "external_destination": True,
                        "base64_encoded_data": True
                    }
                }),
                "severity": "critical",
                "description": "Command and Control beaconing behavior"
            },
            {
                "name": "Rogue DHCP Server Detection",
                "rule_type": ThreatRuleType.SIGNATURE,
                "rule_content": json.dumps({
                    "type": "rogue_dhcp",
                    "conditions": {
                        "dhcp_offer_from_unknown": True,
                        "multiple_dhcp_servers": True,
                        "suspicious_dns_servers": ["8.8.8.8", "1.1.1.1"],
                        "gateway_changes": True
                    }
                }),
                "severity": "high",
                "description": "Unauthorized DHCP server detected"
            },
            {
                "name": "IoT Device Hijacking",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "device_hijacking",
                    "conditions": {
                        "unexpected_destinations": True,
                        "firmware_modification_attempts": True,
                        "configuration_changes": True,
                        "privilege_escalation": True
                    }
                }),
                "severity": "critical",
                "description": "IoT device appears to be compromised"
            },
            {
                "name": "Network Reconnaissance",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "reconnaissance",
                    "conditions": {
                        "network_discovery_tools": ["nmap", "masscan", "zmap"],
                        "service_enumeration": True,
                        "vulnerability_scanning": True,
                        "banner_grabbing": True
                    }
                }),
                "severity": "medium",
                "description": "Network reconnaissance activity"
            },
            {
                "name": "Insider Threat Detection",
                "rule_type": ThreatRuleType.BEHAVIORAL,
                "rule_content": json.dumps({
                    "type": "insider_threat",
                    "conditions": {
                        "after_hours_access": True,
                        "sensitive_data_access": True,
                        "privilege_abuse": True,
                        "unusual_geographic_access": True
                    }
                }),
                "severity": "high",
                "description": "Potential insider threat activity"
            },
            {
                "name": "IoT Botnet Communication",
                "rule_type": ThreatRuleType.SIGNATURE,
                "rule_content": json.dumps({
                    "type": "iot_botnet",
                    "conditions": {
                        "irc_communication": True,
                        "peer_to_peer_protocols": ["BitTorrent", "Kademlia"],
                        "encrypted_c2_channels": True,
                        "coordinated_actions": True
                    }
                }),
                "severity": "critical",
                "description": "IoT device participating in botnet"
            },
            {
                "name": "Firmware Tampering Detection",
                "rule_type": ThreatRuleType.SIGNATURE,
                "rule_content": json.dumps({
                    "type": "firmware_tampering",
                    "conditions": {
                        "firmware_upload_attempts": True,
                        "bootloader_modifications": True,
                        "checksum_mismatches": True,
                        "unsigned_firmware": True
                    }
                }),
                "severity": "critical",
                "description": "Firmware tampering or modification detected"
            }
        ]
        
        for rule_data in default_rules:
            rule = ThreatRule(**rule_data)
            self.rules.append(rule)
            
        logger.info(f"Loaded {len(self.rules)} threat detection rules")
    
    async def analyze_packet(self, packet: Packet, db: Session):
        """Analyze packet for threats"""
        try:
            # Get packet analysis
            packet_analysis = self.packet_analyzer.analyze_packet(packet)
            
            # Check against all rules
            for rule in self.rules:
                if not rule.is_enabled:
                    continue
                    
                threat_detected = await self._evaluate_rule(rule, packet, packet_analysis, db)
                
                if threat_detected:
                    await self._create_alert(rule, packet, packet_analysis, db)
                    
        except Exception as e:
            logger.error(f"Error analyzing packet for threats: {e}")
    
    async def _evaluate_rule(self, rule: ThreatRule, packet: Packet, analysis: Dict, db: Session) -> bool:
        """Evaluate if a rule matches the current packet"""
        try:
            rule_config = json.loads(rule.rule_content)
            rule_type = rule_config.get("type")
            conditions = rule_config.get("conditions", {})
            
            if rule_type == "outbound_connection":
                return self._check_outbound_connection(analysis, conditions)
            elif rule_type == "data_volume":
                return await self._check_data_volume(analysis, conditions, db)
            elif rule_type == "dns_anomaly":
                return self._check_dns_anomaly(analysis, conditions)
            elif rule_type == "botnet_communication":
                return await self._check_botnet_communication(analysis, conditions, db)
            elif rule_type == "protocol_violation":
                return self._check_protocol_violation(analysis, conditions, db)
            elif rule_type == "brute_force":
                return await self._check_brute_force(analysis, conditions, db)
            elif rule_type == "malicious_ip":
                return await self._check_malicious_ip(analysis, conditions)
            elif rule_type == "port_scan":
                return await self._check_port_scan(analysis, conditions, db)
            elif rule_type == "time_based_anomaly":
                return self._check_time_based_anomaly(analysis, conditions, db)
            elif rule_type == "crypto_mining":
                return self._check_crypto_mining(analysis, conditions)
            elif rule_type == "ddos_attack":
                return await self._check_ddos_attack(analysis, conditions, db)
            elif rule_type == "lateral_movement":
                return await self._check_lateral_movement(analysis, conditions, db)
            elif rule_type == "data_exfiltration":
                return self._check_data_exfiltration(analysis, conditions)
            elif rule_type == "c2_beaconing":
                return await self._check_c2_beaconing(analysis, conditions, db)
            elif rule_type == "rogue_dhcp":
                return self._check_rogue_dhcp(analysis, conditions)
            elif rule_type == "device_hijacking":
                return await self._check_device_hijacking(analysis, conditions, db)
            elif rule_type == "reconnaissance":
                return self._check_reconnaissance(analysis, conditions)
            elif rule_type == "insider_threat":
                return await self._check_insider_threat(analysis, conditions, db)
            elif rule_type == "iot_botnet":
                return self._check_iot_botnet(analysis, conditions)
            elif rule_type == "firmware_tampering":
                return self._check_firmware_tampering(analysis, conditions)
                
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.name}: {e}")
            
        return False
    
    def _check_outbound_connection(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for suspicious outbound connections"""
        basic_info = analysis.get("basic_info", {})
        
        if not conditions.get("external_only", False):
            return False
            
        dst_port = basic_info.get("dst_port")
        protocol = basic_info.get("protocols", [])
        
        if dst_port in conditions.get("destination_ports", []):
            if any(p in protocol for p in conditions.get("protocols", [])):
                # Check if destination is external
                dst_ip = basic_info.get("dst_ip", "")
                if not self._is_local_ip(dst_ip):
                    return True
        
        return False
    
    async def _check_data_volume(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for unusual data volume"""
        basic_info = analysis.get("basic_info", {})
        packet_size = basic_info.get("packet_size", 0)
        src_ip = basic_info.get("src_ip")
        
        # This would need to be implemented with time series data
        # For now, just check packet size
        threshold_bytes = conditions.get("threshold_mbps", 10) * 1024 * 1024
        
        return packet_size > threshold_bytes / 100  # Simplified check
    
    def _check_dns_anomaly(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for DNS anomalies like tunneling"""
        protocol_analysis = analysis.get("protocol_analysis", {})
        dns_analysis = protocol_analysis.get("dns", {})
        
        if not dns_analysis:
            return False
        
        queries = dns_analysis.get("queries", [])
        
        for query in queries:
            query_name = query.get("name", "")
            
            # Check query length
            if len(query_name) > conditions.get("query_length_threshold", 100):
                return True
            
            # Check subdomain count
            subdomain_count = query_name.count('.')
            if subdomain_count > conditions.get("subdomain_count_threshold", 10):
                return True
            
            # Check entropy (simplified)
            if len(set(query_name)) / len(query_name) > conditions.get("entropy_threshold", 4.0) / 8:
                return True
        
        return False
    
    async def _check_botnet_communication(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for botnet communication patterns"""
        basic_info = analysis.get("basic_info", {})
        
        # This would need session tracking and timing analysis
        # Simplified implementation
        if conditions.get("external_ips", False):
            dst_ip = basic_info.get("dst_ip", "")
            if not self._is_local_ip(dst_ip):
                # Check if it's encrypted
                security_analysis = analysis.get("security_analysis", {})
                is_encrypted = security_analysis.get("is_encrypted", False)
                
                if not is_encrypted and conditions.get("encrypted", True):
                    return True
        
        return False
    
    def _check_protocol_violation(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for unexpected protocol usage"""
        protocol_analysis = analysis.get("protocol_analysis", {})
        iot_protocol = protocol_analysis.get("iot_protocol", {})
        
        if iot_protocol:
            protocol_name = iot_protocol.get("protocol", "")
            
            if protocol_name in conditions.get("unexpected_protocols", []):
                # Would need to check device type from database
                return True
        
        return False
    
    async def _check_brute_force(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for brute force attacks"""
        basic_info = analysis.get("basic_info", {})
        dst_port = basic_info.get("dst_port")
        
        # Simplified check - would need connection tracking
        if dst_port in conditions.get("target_ports", []):
            # This would need to track failed connection attempts over time
            return False
        
        return False
    
    async def _check_malicious_ip(self, analysis: Dict, conditions: Dict) -> bool:
        """Check against IP reputation databases"""
        basic_info = analysis.get("basic_info", {})
        dst_ip = basic_info.get("dst_ip", "")
        
        # Simplified - would integrate with actual threat intelligence feeds
        suspicious_ranges = ["10.0.0.1", "192.168.1.100"]  # Placeholder
        
        return dst_ip in suspicious_ranges
    
    async def _check_port_scan(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for port scanning activity"""
        basic_info = analysis.get("basic_info", {})
        tcp_flags = basic_info.get("tcp_flags", 0)
        
        # Check for SYN-only packets (potential scan)
        if conditions.get("tcp_syn_only", False):
            if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN without ACK
                return True
        
        return False
    
    def _check_time_based_anomaly(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for time-based anomalies"""
        current_time = datetime.now().time()
        time_range = conditions.get("time_range", {})
        
        start_time = datetime.strptime(time_range.get("start", "00:00"), "%H:%M").time()
        end_time = datetime.strptime(time_range.get("end", "23:59"), "%H:%M").time()
        
        if start_time <= current_time <= end_time or (start_time > end_time and (current_time >= start_time or current_time <= end_time)):
            # Activity during specified time range
            return True
        
        return False
    
    def _check_crypto_mining(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for cryptocurrency mining indicators"""
        basic_info = analysis.get("basic_info", {})
        protocol_analysis = analysis.get("protocol_analysis", {})
        
        dst_port = basic_info.get("dst_port")
        if dst_port in conditions.get("mining_ports", []):
            return True
        
        # Check DNS queries for mining pools
        dns_analysis = protocol_analysis.get("dns", {})
        if dns_analysis:
            queries = dns_analysis.get("queries", [])
            mining_domains = conditions.get("mining_pool_domains", [])
            
            for query in queries:
                query_name = query.get("name", "")
                for pattern in mining_domains:
                    if re.match(pattern, query_name):
                        return True
        
        return False
    
    async def _create_alert(self, rule: ThreatRule, packet: Packet, analysis: Dict, db: Session):
        """Create alert for detected threat"""
        basic_info = analysis.get("basic_info", {})
        
        # Find associated device
        device = None
        src_ip = basic_info.get("src_ip")
        if src_ip:
            device = db.query(Device).filter(Device.ip_address == src_ip).first()
        
        alert = Alert(
            title=f"{rule.name} - {src_ip or 'Unknown'}",
            description=rule.description,
            severity=AlertSeverity(rule.severity),
            status=AlertStatus.OPEN,
            source_ip=basic_info.get("src_ip"),
            destination_ip=basic_info.get("dst_ip"),
            source_port=basic_info.get("src_port"),
            destination_port=basic_info.get("dst_port"),
            protocol=basic_info.get("protocols", ["Unknown"])[0] if basic_info.get("protocols") else "Unknown",
            device_id=device.id if device else None,
            rule_id=rule.id if hasattr(rule, 'id') else None,
            raw_data=json.dumps(analysis)
        )
        
        db.add(alert)
        db.commit()
        
        logger.warning(f"Alert created: {alert.title} - {alert.severity.value}")
    
    async def _check_ddos_attack(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for DDoS attack patterns"""
        basic_info = analysis.get("basic_info", {})
        packet_size = basic_info.get("packet_size", 0)
        
        # Simplified check - would need rate tracking
        if packet_size < 64:  # Small packet size could indicate flood
            return True
        return False
    
    async def _check_lateral_movement(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for lateral movement patterns"""
        basic_info = analysis.get("basic_info", {})
        dst_port = basic_info.get("dst_port")
        
        if dst_port in conditions.get("internal_scan_ports", []):
            dst_ip = basic_info.get("dst_ip", "")
            if self._is_local_ip(dst_ip):
                return True
        return False
    
    def _check_data_exfiltration(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for data exfiltration patterns"""
        basic_info = analysis.get("basic_info", {})
        packet_size = basic_info.get("packet_size", 0)
        
        # Check for large uploads
        threshold_bytes = conditions.get("upload_volume_threshold_mb", 100) * 1024 * 1024
        if packet_size > threshold_bytes / 1000:  # Simplified check
            return True
        return False
    
    async def _check_c2_beaconing(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for command and control beaconing"""
        basic_info = analysis.get("basic_info", {})
        dst_ip = basic_info.get("dst_ip", "")
        
        # Check if external destination
        if not self._is_local_ip(dst_ip) and conditions.get("external_destination", False):
            # Would need timing analysis for actual beaconing detection
            return False
        return False
    
    def _check_rogue_dhcp(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for rogue DHCP server"""
        basic_info = analysis.get("basic_info", {})
        dst_port = basic_info.get("dst_port")
        src_port = basic_info.get("src_port")
        
        # Check for DHCP traffic
        if dst_port == 67 or src_port == 67 or dst_port == 68 or src_port == 68:
            return True
        return False
    
    async def _check_device_hijacking(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for IoT device hijacking"""
        basic_info = analysis.get("basic_info", {})
        src_ip = basic_info.get("src_ip", "")
        
        # Check if device behavior is unusual
        if self._is_local_ip(src_ip):
            dst_ip = basic_info.get("dst_ip", "")
            if not self._is_local_ip(dst_ip):
                return True
        return False
    
    def _check_reconnaissance(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for network reconnaissance"""
        basic_info = analysis.get("basic_info", {})
        tcp_flags = basic_info.get("tcp_flags", 0)
        
        # Check for scanning patterns
        if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN without ACK
            return True
        return False
    
    async def _check_insider_threat(self, analysis: Dict, conditions: Dict, db: Session) -> bool:
        """Check for insider threat patterns"""
        current_time = datetime.now().time()
        
        # Check for after-hours activity
        if conditions.get("after_hours_access", False):
            if current_time.hour >= 22 or current_time.hour <= 6:
                return True
        return False
    
    def _check_iot_botnet(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for IoT botnet communication"""
        protocol_analysis = analysis.get("protocol_analysis", {})
        
        # Check for IRC communication
        if conditions.get("irc_communication", False):
            basic_info = analysis.get("basic_info", {})
            dst_port = basic_info.get("dst_port")
            if dst_port in [6667, 6697, 194]:  # Common IRC ports
                return True
        return False
    
    def _check_firmware_tampering(self, analysis: Dict, conditions: Dict) -> bool:
        """Check for firmware tampering"""
        basic_info = analysis.get("basic_info", {})
        dst_port = basic_info.get("dst_port")
        
        # Check for firmware update ports
        if dst_port in [69, 80, 443, 8080]:  # TFTP, HTTP, HTTPS
            content_analysis = analysis.get("content_analysis", {})
            if content_analysis.get("has_payload", False):
                return True
        return False
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is in local network ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False