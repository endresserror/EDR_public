import pytest
import asyncio
import json
from unittest.mock import Mock, patch
from datetime import datetime

# Basic imports test
def test_imports():
    """Test that all core modules can be imported"""
    try:
        from core.database import Base, get_db, init_db
        from core.config import settings
        from models.device import Device, DeviceType
        from models.alert import Alert, AlertSeverity, AlertStatus
        from models.network_session import NetworkSession
        from models.threat_rule import ThreatRule, ThreatRuleType
        from models.system_log import SystemLog, LogLevel
        from services.device_profiler import DeviceProfiler
        from services.packet_analyzer import PacketAnalyzer
        from services.threat_engine import ThreatEngine
        from utils.logger import setup_logger
        assert True
    except ImportError as e:
        pytest.fail(f"Import error: {e}")

def test_device_profiler():
    """Test device profiler functionality"""
    from services.device_profiler import DeviceProfiler
    
    profiler = DeviceProfiler()
    
    # Test manufacturer detection
    manufacturer = profiler._get_manufacturer("AC:DE:48:00:11:22")
    assert manufacturer == "Apple"
    
    manufacturer = profiler._get_manufacturer("DC:A6:32:00:11:22")
    assert manufacturer == "Raspberry Pi Foundation"
    
    # Test device classification
    profile = {
        "hostname": "iphone-john",
        "manufacturer": "Apple"
    }
    device_type = profiler._classify_device(profile)
    assert device_type == "mobile_device"
    
    profile = {
        "hostname": "raspberry-pi",
        "manufacturer": "Raspberry Pi Foundation"
    }
    device_type = profiler._classify_device(profile)
    assert device_type == "single_board_computer"

def test_packet_analyzer():
    """Test packet analyzer functionality"""
    from services.packet_analyzer import PacketAnalyzer
    
    analyzer = PacketAnalyzer()
    
    # Test entropy calculation
    high_entropy_data = b"A" * 100 + b"B" * 100 + b"C" * 100
    low_entropy_data = b"A" * 300
    
    high_entropy = analyzer._calculate_entropy(high_entropy_data)
    low_entropy = analyzer._calculate_entropy(low_entropy_data)
    
    assert high_entropy > low_entropy
    
    # Test printable ratio
    printable_data = b"Hello World"
    non_printable_data = bytes(range(256))
    
    printable_ratio_high = analyzer._calculate_printable_ratio(printable_data)
    printable_ratio_low = analyzer._calculate_printable_ratio(non_printable_data)
    
    assert printable_ratio_high > printable_ratio_low

@pytest.mark.asyncio
async def test_threat_engine():
    """Test threat engine functionality"""
    from services.threat_engine import ThreatEngine
    
    engine = ThreatEngine()
    await engine.load_rules()
    
    # Test that rules are loaded
    assert len(engine.rules) > 0
    
    # Test rule types
    rule_types = [rule.rule_type.value for rule in engine.rules if rule.rule_type]
    assert "behavioral" in rule_types
    assert "anomaly" in rule_types
    assert "signature" in rule_types

def test_database_models():
    """Test database model creation"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.database import Base
    from models.device import Device, DeviceType
    from models.alert import Alert, AlertSeverity, AlertStatus
    from models.network_session import NetworkSession
    from models.threat_rule import ThreatRule, ThreatRuleType
    from models.system_log import SystemLog, LogLevel
    
    # Create in-memory SQLite database for testing
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Test Device model
        device = Device(
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            hostname="test-device",
            device_type=DeviceType.CAMERA,
            manufacturer="Test Manufacturer",
            is_active=True,
            trust_score=0.8
        )
        db.add(device)
        db.commit()
        
        # Test Alert model
        alert = Alert(
            title="Test Alert",
            description="Test alert description",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.OPEN,
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            protocol="TCP"
        )
        db.add(alert)
        db.commit()
        
        # Test NetworkSession model
        session = NetworkSession(
            session_id="test-session-123",
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            protocol="TCP",
            bytes_sent=1024,
            bytes_received=2048,
            packets_sent=10,
            packets_received=20,
            is_encrypted=True,
            is_suspicious=False,
            start_time=datetime.now()
        )
        db.add(session)
        db.commit()
        
        # Test ThreatRule model
        rule = ThreatRule(
            name="Test Rule",
            description="Test threat rule",
            rule_type=ThreatRuleType.SIGNATURE,
            rule_content='{"type": "test", "conditions": {}}',
            severity="medium",
            is_enabled=True,
            confidence=75
        )
        db.add(rule)
        db.commit()
        
        # Test SystemLog model
        log = SystemLog(
            level=LogLevel.INFO,
            component="test",
            message="Test log message"
        )
        db.add(log)
        db.commit()
        
        # Verify records were created
        assert db.query(Device).count() == 1
        assert db.query(Alert).count() == 1
        assert db.query(NetworkSession).count() == 1
        assert db.query(ThreatRule).count() == 1
        assert db.query(SystemLog).count() == 1
        
    finally:
        db.close()

def test_logger_setup():
    """Test logger configuration"""
    from utils.logger import setup_logger
    
    logger = setup_logger("test_logger")
    
    assert logger.name == "test_logger"
    assert len(logger.handlers) >= 2  # Console and file handlers

def test_config_loading():
    """Test configuration loading"""
    from core.config import settings
    
    assert settings.app_name == "IoT EDR System"
    assert settings.version == "1.0.0"
    assert isinstance(settings.debug, bool)
    assert isinstance(settings.trusted_networks, list)
    assert isinstance(settings.monitored_ports, list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])