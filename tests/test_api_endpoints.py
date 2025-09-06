import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from datetime import datetime

@pytest.fixture
def client():
    """Create test client"""
    from main import app
    return TestClient(app)

def test_root_endpoint(client):
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "IoT EDR System" in data["message"]

def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert data["status"] == "healthy"

@patch('api.routers.dashboard.get_db')
def test_dashboard_overview(mock_get_db, client):
    """Test dashboard overview endpoint"""
    # Mock database session
    mock_db = Mock()
    mock_get_db.return_value = mock_db
    
    # Mock query results
    mock_db.query.return_value.count.return_value = 5
    mock_db.query.return_value.filter.return_value.count.return_value = 3
    mock_db.func.sum.return_value.scalar.return_value = 1024000
    
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert "time_period_hours" in data
    assert "system_health" in data
    assert "devices" in data
    assert "security" in data
    assert "network" in data

@patch('api.routers.devices.get_db')
def test_devices_endpoint(mock_get_db, client):
    """Test devices endpoint"""
    # Mock database session
    mock_db = Mock()
    mock_get_db.return_value = mock_db
    
    # Mock device data
    mock_device = Mock()
    mock_device.id = 1
    mock_device.mac_address = "00:11:22:33:44:55"
    mock_device.ip_address = "192.168.1.100"
    mock_device.hostname = "test-device"
    mock_device.device_type = Mock()
    mock_device.device_type.value = "camera"
    mock_device.manufacturer = "Test Manufacturer"
    mock_device.is_active = True
    mock_device.trust_score = 0.8
    mock_device.last_seen = datetime.now()
    mock_device.first_seen = datetime.now()
    mock_device.created_at = datetime.now()
    mock_device.updated_at = datetime.now()
    
    mock_db.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_device]
    
    response = client.get("/api/v1/devices")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        device = data[0]
        assert "id" in device
        assert "mac_address" in device
        assert "ip_address" in device

@patch('api.routers.alerts.get_db')
def test_alerts_endpoint(mock_get_db, client):
    """Test alerts endpoint"""
    # Mock database session
    mock_db = Mock()
    mock_get_db.return_value = mock_db
    
    # Mock alert data
    mock_alert = Mock()
    mock_alert.id = 1
    mock_alert.title = "Test Alert"
    mock_alert.description = "Test alert description"
    mock_alert.severity = Mock()
    mock_alert.severity.value = "high"
    mock_alert.status = Mock()
    mock_alert.status.value = "open"
    mock_alert.source_ip = "192.168.1.100"
    mock_alert.destination_ip = "8.8.8.8"
    mock_alert.protocol = "TCP"
    mock_alert.is_acknowledged = False
    mock_alert.created_at = datetime.now()
    mock_alert.updated_at = datetime.now()
    
    mock_db.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_alert]
    
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        alert = data[0]
        assert "id" in alert
        assert "title" in alert
        assert "severity" in alert

@patch('api.routers.sessions.get_db')
def test_sessions_endpoint(mock_get_db, client):
    """Test network sessions endpoint"""
    # Mock database session
    mock_db = Mock()
    mock_get_db.return_value = mock_db
    
    # Mock session data
    mock_session = Mock()
    mock_session.id = 1
    mock_session.session_id = "test-session-123"
    mock_session.source_ip = "192.168.1.100"
    mock_session.destination_ip = "8.8.8.8"
    mock_session.protocol = "TCP"
    mock_session.bytes_sent = 1024
    mock_session.bytes_received = 2048
    mock_session.is_encrypted = True
    mock_session.is_suspicious = False
    mock_session.start_time = datetime.now()
    mock_session.created_at = datetime.now()
    
    mock_db.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_session]
    
    response = client.get("/api/v1/sessions")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        session = data[0]
        assert "id" in session
        assert "source_ip" in session
        assert "destination_ip" in session

@patch('api.routers.rules.get_db')
def test_rules_endpoint(mock_get_db, client):
    """Test threat rules endpoint"""
    # Mock database session
    mock_db = Mock()
    mock_get_db.return_value = mock_db
    
    # Mock rule data
    mock_rule = Mock()
    mock_rule.id = 1
    mock_rule.name = "Test Rule"
    mock_rule.description = "Test threat rule"
    mock_rule.rule_type = Mock()
    mock_rule.rule_type.value = "signature"
    mock_rule.severity = "medium"
    mock_rule.is_enabled = True
    mock_rule.confidence = 75
    mock_rule.tags = "test,sample"
    mock_rule.created_at = datetime.now()
    mock_rule.updated_at = datetime.now()
    
    mock_db.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_rule]
    
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        rule = data[0]
        assert "id" in rule
        assert "name" in rule
        assert "rule_type" in rule

@patch('api.routers.logs.get_db')
def test_logs_endpoint(mock_get_db, client):
    """Test system logs endpoint"""
    # Mock database session
    mock_db = Mock()
    mock_get_db.return_value = mock_db
    
    # Mock log data
    mock_log = Mock()
    mock_log.id = 1
    mock_log.level = Mock()
    mock_log.level.value = "info"
    mock_log.component = "test"
    mock_log.message = "Test log message"
    mock_log.details = None
    mock_log.ip_address = None
    mock_log.user_agent = None
    mock_log.created_at = datetime.now()
    
    mock_db.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_log]
    
    response = client.get("/api/v1/logs")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        log = data[0]
        assert "id" in log
        assert "level" in log
        assert "message" in log

def test_api_error_handling(client):
    """Test API error handling"""
    # Test 404 for non-existent endpoint
    response = client.get("/api/v1/nonexistent")
    assert response.status_code == 404
    
    # Test 404 for non-existent device
    response = client.get("/api/v1/devices/99999")
    assert response.status_code == 404

if __name__ == "__main__":
    pytest.main([__file__, "-v"])