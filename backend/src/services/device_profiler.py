import requests
import socket
import subprocess
import re
from typing import Dict, Optional
from scapy.all import ARP, Ether, srp
from utils.logger import setup_logger

logger = setup_logger(__name__)

class DeviceProfiler:
    def __init__(self):
        self.oui_database = {}
        self._load_oui_database()
    
    def _load_oui_database(self):
        """Load OUI database for manufacturer detection"""
        oui_data = {
            "00:50:C2": "Apple",
            "AC:DE:48": "Apple", 
            "B8:E8:56": "Apple",
            "DC:A6:32": "Raspberry Pi Foundation",
            "B8:27:EB": "Raspberry Pi Foundation",
            "00:1B:44": "Cisco",
            "00:26:B9": "Cisco",
            "58:97:BD": "Tp-Link",
            "EC:08:6B": "Tp-Link",
            "50:C7:BF": "Tp-Link",
            "18:E8:29": "Google",
            "F4:F5:D8": "Google",
            "CC:32:E5": "Google Nest",
            "00:15:99": "Samsung",
            "EC:1F:72": "Samsung",
            "78:4F:43": "Amazon",
            "50:DC:E7": "Amazon",
            "AC:63:BE": "Amazon",
            "F0:27:2D": "Amazon Echo",
            "34:D2:70": "Espressif (ESP32)",
            "30:AE:A4": "Espressif (ESP32)",
            "24:6F:28": "Espressif (ESP8266)",
            "5C:CF:7F": "Espressif (ESP8266)",
        }
        self.oui_database.update(oui_data)
    
    def profile_device(self, ip: str, mac: str, packet=None) -> Dict[str, str]:
        """Profile device based on IP, MAC, and packet analysis"""
        profile = {
            "ip_address": ip,
            "mac_address": mac,
            "manufacturer": self._get_manufacturer(mac),
            "hostname": self._get_hostname(ip),
            "device_type": "unknown",
            "model": None,
            "os": None,
            "services": []
        }
        
        profile["device_type"] = self._classify_device(profile)
        
        return profile
    
    def _get_manufacturer(self, mac: str) -> Optional[str]:
        """Get manufacturer from MAC address OUI"""
        if not mac or len(mac) < 8:
            return None
            
        oui = mac[:8].upper()
        return self.oui_database.get(oui, "Unknown")
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname via reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _classify_device(self, profile: Dict) -> str:
        """Classify device type based on available information"""
        hostname = profile.get("hostname", "").lower()
        manufacturer = profile.get("manufacturer", "").lower()
        
        if "apple" in manufacturer:
            if "iphone" in hostname or "ipad" in hostname:
                return "mobile_device"
            elif "appletv" in hostname:
                return "smart_tv"
            elif "macbook" in hostname or "imac" in hostname:
                return "computer"
            else:
                return "apple_device"
        
        elif "raspberry" in manufacturer:
            return "single_board_computer"
        
        elif "espressif" in manufacturer or "esp32" in hostname or "esp8266" in hostname:
            return "iot_sensor"
        
        elif "amazon" in manufacturer:
            if "echo" in hostname or "alexa" in hostname:
                return "smart_speaker"
            else:
                return "amazon_device"
        
        elif "google" in manufacturer:
            if "nest" in hostname or "chromecast" in hostname:
                return "smart_home"
            else:
                return "google_device"
        
        elif "cisco" in manufacturer or "tp-link" in manufacturer:
            return "network_device"
        
        elif "samsung" in manufacturer:
            if "tv" in hostname or "smarttv" in hostname:
                return "smart_tv"
            elif "fridge" in hostname or "washing" in hostname:
                return "smart_appliance"
            else:
                return "samsung_device"
        
        # Check for common IoT device patterns in hostname
        iot_patterns = [
            "camera", "cam", "ipcam", "surveillance",
            "thermostat", "nest", "ecobee",
            "bulb", "light", "philips", "hue",
            "plug", "switch", "outlet",
            "sensor", "motion", "door", "window",
            "speaker", "sonos", "alexa", "echo",
            "roku", "firetv", "chromecast",
            "printer", "hp", "canon", "epson"
        ]
        
        for pattern in iot_patterns:
            if pattern in hostname:
                return self._get_device_type_by_pattern(pattern)
        
        return "unknown"
    
    def _get_device_type_by_pattern(self, pattern: str) -> str:
        """Get device type based on hostname pattern"""
        pattern_map = {
            "camera": "camera", "cam": "camera", "ipcam": "camera", "surveillance": "camera",
            "thermostat": "thermostat", "nest": "thermostat", "ecobee": "thermostat",
            "bulb": "light_bulb", "light": "light_bulb", "philips": "light_bulb", "hue": "light_bulb",
            "plug": "smart_plug", "switch": "smart_plug", "outlet": "smart_plug",
            "sensor": "sensor", "motion": "sensor", "door": "sensor", "window": "sensor",
            "speaker": "smart_speaker", "sonos": "smart_speaker", "alexa": "smart_speaker", "echo": "smart_speaker",
            "roku": "smart_tv", "firetv": "smart_tv", "chromecast": "smart_tv",
            "printer": "printer", "hp": "printer", "canon": "printer", "epson": "printer"
        }
        
        return pattern_map.get(pattern, "unknown")
    
    def get_device_services(self, ip: str) -> list:
        """Scan for common services on device"""
        common_ports = [22, 23, 80, 135, 139, 443, 445, 1883, 5683, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        services = []
        for port in open_ports:
            service = self._identify_service(port)
            if service:
                services.append(service)
        
        return services
    
    def _identify_service(self, port: int) -> Optional[str]:
        """Identify service running on port"""
        service_map = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            135: "RPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1883: "MQTT",
            5683: "CoAP",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        
        return service_map.get(port)