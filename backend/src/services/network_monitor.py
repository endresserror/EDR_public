import asyncio
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from typing import Optional, Dict, Set
from datetime import datetime, timedelta
import threading
import queue
import hashlib
from sqlalchemy.orm import Session

from core.database import get_db
from core.config import settings
from models.device import Device, DeviceType
from models.network_session import NetworkSession
from services.device_profiler import DeviceProfiler
from utils.logger import setup_logger

logger = setup_logger(__name__)

class NetworkMonitor:
    def __init__(self, threat_engine):
        self.threat_engine = threat_engine
        self.device_profiler = DeviceProfiler()
        self.is_running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.sessions: Dict[str, dict] = {}
        self.known_devices: Set[str] = set()
        self.monitor_thread = None
        self.processor_thread = None
        
    async def start_monitoring(self):
        """Start network monitoring"""
        if self.is_running:
            return
            
        self.is_running = True
        logger.info(f"Starting network monitoring on interface: {settings.network_interface}")
        
        self.monitor_thread = threading.Thread(target=self._packet_capture_thread)
        self.processor_thread = threading.Thread(target=self._packet_processor_thread)
        
        self.monitor_thread.start()
        self.processor_thread.start()
        
        logger.info("Network monitoring started successfully")
    
    async def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        if self.processor_thread:
            self.processor_thread.join(timeout=5)
            
        logger.info("Network monitoring stopped")
    
    def _packet_capture_thread(self):
        """Thread for capturing packets"""
        try:
            scapy.sniff(
                iface=settings.network_interface,
                prn=self._packet_handler,
                store=0,
                stop_filter=lambda x: not self.is_running,
                filter=settings.capture_filter or None
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.is_running = False
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        if not self.is_running:
            return
            
        try:
            if self.packet_queue.qsize() < 9000:
                self.packet_queue.put(packet, block=False)
        except queue.Full:
            logger.warning("Packet queue full, dropping packet")
    
    def _packet_processor_thread(self):
        """Thread for processing packets"""
        db = next(get_db())
        
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1.0)
                self._process_packet(packet, db)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Packet processing error: {e}")
                
        db.close()
    
    def _process_packet(self, packet, db: Session):
        """Process individual packet"""
        try:
            if not packet.haslayer(IP):
                return
                
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            self._update_device_info(src_ip, packet, db)
            self._update_device_info(dst_ip, packet, db)
            
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                self._process_session(packet, db)
            
            asyncio.run(self.threat_engine.analyze_packet(packet, db))
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_device_info(self, ip: str, packet, db: Session):
        """Update device information"""
        if ip in ["0.0.0.0", "255.255.255.255"]:
            return
            
        mac_address = None
        if packet.haslayer(Ether):
            if packet[IP].src == ip:
                mac_address = packet[Ether].src
            elif packet[IP].dst == ip:
                mac_address = packet[Ether].dst
        
        if not mac_address or mac_address in self.known_devices:
            return
            
        device = db.query(Device).filter(Device.mac_address == mac_address).first()
        
        if not device:
            device_info = self.device_profiler.profile_device(ip, mac_address, packet)
            
            device = Device(
                mac_address=mac_address,
                ip_address=ip,
                hostname=device_info.get("hostname"),
                device_type=DeviceType(device_info.get("device_type", "unknown")),
                manufacturer=device_info.get("manufacturer"),
                model=device_info.get("model"),
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            
            db.add(device)
            db.commit()
            
            logger.info(f"New device discovered: {ip} ({mac_address}) - {device_info.get('device_type', 'unknown')}")
        else:
            device.last_seen = datetime.now()
            if device.ip_address != ip:
                device.ip_address = ip
            db.commit()
        
        self.known_devices.add(mac_address)
    
    def _process_session(self, packet, db: Session):
        """Process network session"""
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return
            
        ip_layer = packet[IP]
        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        
        session_id = self._generate_session_id(
            ip_layer.src, ip_layer.dst,
            transport_layer.sport, transport_layer.dport,
            "TCP" if packet.haslayer(TCP) else "UDP"
        )
        
        packet_size = len(packet)
        
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "src_port": transport_layer.sport,
                "dst_port": transport_layer.dport,
                "protocol": "TCP" if packet.haslayer(TCP) else "UDP",
                "bytes_sent": 0,
                "bytes_received": 0,
                "packets_sent": 0,
                "packets_received": 0,
                "start_time": datetime.now(),
                "last_activity": datetime.now(),
                "is_encrypted": self._detect_encryption(packet)
            }
        
        session = self.sessions[session_id]
        session["last_activity"] = datetime.now()
        session["bytes_sent"] += packet_size
        session["packets_sent"] += 1
        
        self._cleanup_old_sessions(db)
    
    def _generate_session_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Generate unique session ID"""
        session_str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return hashlib.md5(session_str.encode()).hexdigest()
    
    def _detect_encryption(self, packet) -> bool:
        """Detect if traffic is encrypted"""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.dport in [443, 993, 995, 636, 22] or tcp_layer.sport in [443, 993, 995, 636, 22]:
                return True
        return False
    
    def _cleanup_old_sessions(self, db: Session):
        """Clean up old sessions and save to database"""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        sessions_to_remove = []
        
        for session_id, session_data in self.sessions.items():
            if session_data["last_activity"] < cutoff_time:
                device = db.query(Device).filter(Device.ip_address == session_data["src_ip"]).first()
                
                network_session = NetworkSession(
                    session_id=session_id,
                    source_ip=session_data["src_ip"],
                    destination_ip=session_data["dst_ip"],
                    source_port=session_data["src_port"],
                    destination_port=session_data["dst_port"],
                    protocol=session_data["protocol"],
                    bytes_sent=session_data["bytes_sent"],
                    bytes_received=session_data["bytes_received"],
                    packets_sent=session_data["packets_sent"],
                    packets_received=session_data["packets_received"],
                    duration=int((session_data["last_activity"] - session_data["start_time"]).total_seconds()),
                    is_encrypted=session_data["is_encrypted"],
                    device_id=device.id if device else None,
                    start_time=session_data["start_time"],
                    end_time=session_data["last_activity"]
                )
                
                db.add(network_session)
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self.sessions[session_id]
        
        if sessions_to_remove:
            db.commit()