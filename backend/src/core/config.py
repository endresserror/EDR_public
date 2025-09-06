from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    app_name: str = "IoT EDR System"
    version: str = "1.0.0"
    debug: bool = False
    
    database_url: str = "sqlite:///./data/iot_edr.db"
    
    network_interface: str = "eth0"
    capture_filter: str = ""
    packet_buffer_size: int = 1024
    
    alert_retention_days: int = 90
    log_retention_days: int = 30
    
    trusted_networks: List[str] = ["192.168.1.0/24", "10.0.0.0/8"]
    monitored_ports: List[int] = [22, 23, 80, 443, 8080, 1883, 5683]
    
    threat_intel_sources: List[str] = []
    max_concurrent_connections: int = 1000
    
    web_dashboard_host: str = "0.0.0.0"
    web_dashboard_port: int = 8000
    
    log_level: str = "INFO"
    log_file: str = "./logs/edr.log"
    
    api_key: Optional[str] = None
    secret_key: str = "your-secret-key-change-this"
    
    class Config:
        env_file = ".env"

settings = Settings()