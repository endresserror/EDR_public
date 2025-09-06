#!/bin/bash

# IoT EDR System Test Script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test basic imports
test_imports() {
    log "Testing basic imports..."
    
    cd backend/src
    
    # Test core imports
    python3 -c "
from core.database import Base, get_db, init_db
from core.config import settings
print('✓ Core imports successful')
"
    
    # Test model imports
    python3 -c "
from models.device import Device, DeviceType
from models.alert import Alert, AlertSeverity, AlertStatus
from models.network_session import NetworkSession
from models.threat_rule import ThreatRule, ThreatRuleType
from models.system_log import SystemLog, LogLevel
print('✓ Model imports successful')
"
    
    # Test utils imports
    python3 -c "
from utils.logger import setup_logger
print('✓ Utils imports successful')
"
    
    cd ../..
    success "Import tests completed"
}

# Test configuration loading
test_configuration() {
    log "Testing configuration loading..."
    
    cd backend/src
    
    python3 -c "
from core.config import settings
assert settings.app_name == 'IoT EDR System'
assert settings.version == '1.0.0'
assert isinstance(settings.debug, bool)
assert isinstance(settings.trusted_networks, list)
assert isinstance(settings.monitored_ports, list)
print('✓ Configuration loading successful')
"
    
    cd ../..
    success "Configuration tests completed"
}

# Test database models
test_database_models() {
    log "Testing database models..."
    
    cd backend/src
    
    python3 -c "
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.database import Base
from models.device import Device, DeviceType
from models.alert import Alert, AlertSeverity, AlertStatus
from models.network_session import NetworkSession
from models.threat_rule import ThreatRule, ThreatRuleType
from models.system_log import SystemLog, LogLevel
from datetime import datetime

# Create in-memory SQLite database for testing
engine = create_engine('sqlite:///:memory:')
Base.metadata.create_all(bind=engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

try:
    # Test Device model
    device = Device(
        mac_address='00:11:22:33:44:55',
        ip_address='192.168.1.100',
        hostname='test-device',
        device_type=DeviceType.CAMERA,
        manufacturer='Test Manufacturer',
        is_active=True,
        trust_score=0.8
    )
    db.add(device)
    db.commit()
    
    # Test Alert model
    alert = Alert(
        title='Test Alert',
        description='Test alert description',
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        source_ip='192.168.1.100',
        destination_ip='8.8.8.8',
        protocol='TCP'
    )
    db.add(alert)
    db.commit()
    
    # Test NetworkSession model
    session = NetworkSession(
        session_id='test-session-123',
        source_ip='192.168.1.100',
        destination_ip='8.8.8.8',
        protocol='TCP',
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
        name='Test Rule',
        description='Test threat rule',
        rule_type=ThreatRuleType.SIGNATURE,
        rule_content='{\"type\": \"test\", \"conditions\": {}}',
        severity='medium',
        is_enabled=True,
        confidence=75
    )
    db.add(rule)
    db.commit()
    
    # Test SystemLog model
    log = SystemLog(
        level=LogLevel.INFO,
        component='test',
        message='Test log message'
    )
    db.add(log)
    db.commit()
    
    # Verify records were created
    assert db.query(Device).count() == 1
    assert db.query(Alert).count() == 1
    assert db.query(NetworkSession).count() == 1
    assert db.query(ThreatRule).count() == 1
    assert db.query(SystemLog).count() == 1
    
    print('✓ Database models test successful')
    
finally:
    db.close()
"
    
    cd ../..
    success "Database model tests completed"
}

# Test logger
test_logger() {
    log "Testing logger functionality..."
    
    cd backend/src
    
    python3 -c "
from utils.logger import setup_logger
import logging

logger = setup_logger('test_logger')
assert logger.name == 'test_logger'
assert len(logger.handlers) >= 1  # At least console handler

# Test logging levels
logger.info('Test info message')
logger.warning('Test warning message')
logger.error('Test error message')

print('✓ Logger test successful')
"
    
    cd ../..
    success "Logger tests completed"
}

# Test file structure
test_file_structure() {
    log "Testing file structure..."
    
    # Check essential files exist
    essential_files=(
        "backend/requirements.txt"
        "backend/src/main.py"
        "backend/src/core/database.py"
        "backend/src/core/config.py"
        "backend/src/models/device.py"
        "backend/src/models/alert.py"
        "backend/src/services/network_monitor.py"
        "backend/src/services/packet_analyzer.py"
        "backend/src/services/threat_engine.py"
        "backend/src/utils/logger.py"
        "frontend/package.json"
        "frontend/src/App.tsx"
        "frontend/src/main.tsx"
        "docker-compose.yml"
        ".env.example"
        "README.md"
    )
    
    for file in "${essential_files[@]}"; do
        if [ -f "$file" ]; then
            echo "✓ $file exists"
        else
            error "$file missing"
            exit 1
        fi
    done
    
    success "File structure tests completed"
}

# Test configuration files
test_config_files() {
    log "Testing configuration files..."
    
    # Check .env.example has required variables
    required_vars=(
        "DATABASE_URL"
        "NETWORK_INTERFACE"
        "SECRET_KEY"
        "WEB_DASHBOARD_HOST"
        "WEB_DASHBOARD_PORT"
    )
    
    for var in "${required_vars[@]}"; do
        if grep -q "^$var=" .env.example; then
            echo "✓ $var defined in .env.example"
        else
            error "$var missing from .env.example"
            exit 1
        fi
    done
    
    success "Configuration file tests completed"
}

# Test Docker configuration
test_docker_config() {
    log "Testing Docker configuration..."
    
    # Check docker-compose.yml syntax
    if command -v docker-compose &> /dev/null; then
        if docker-compose config > /dev/null 2>&1; then
            echo "✓ docker-compose.yml syntax valid"
        else
            warning "docker-compose.yml syntax errors detected"
        fi
    else
        warning "docker-compose not installed, skipping syntax check"
    fi
    
    # Check Dockerfile exists
    if [ -f "backend/Dockerfile" ] && [ -f "frontend/Dockerfile" ]; then
        echo "✓ Dockerfiles exist"
    else
        error "Missing Dockerfiles"
        exit 1
    fi
    
    success "Docker configuration tests completed"
}

# Main test function
main() {
    echo "======================================="
    echo "    IoT EDR System Test Suite         "
    echo "======================================="
    echo
    
    test_file_structure
    test_config_files
    test_docker_config
    test_imports
    test_configuration
    test_database_models
    test_logger
    
    echo
    success "All tests completed successfully!"
    echo
    echo "System appears to be working correctly."
    echo "You can now proceed with installation or deployment."
}

# Run main function
main "$@"