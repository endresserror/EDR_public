from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Dict, Any

from core.database import get_db
from models.device import Device, DeviceType
from models.alert import Alert, AlertSeverity, AlertStatus
from models.network_session import NetworkSession
from models.system_log import SystemLog, LogLevel
from utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

@router.get("/overview")
async def get_dashboard_overview(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get comprehensive dashboard overview"""
    since = datetime.now() - timedelta(hours=hours)
    
    # Device statistics
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.is_active == True).count()
    new_devices = db.query(Device).filter(Device.first_seen >= since).count()
    
    # Alert statistics
    total_alerts = db.query(Alert).filter(Alert.created_at >= since).count()
    critical_alerts = db.query(Alert).filter(
        Alert.created_at >= since,
        Alert.severity == AlertSeverity.CRITICAL
    ).count()
    unresolved_alerts = db.query(Alert).filter(
        Alert.created_at >= since,
        Alert.status == AlertStatus.OPEN
    ).count()
    
    # Network session statistics
    total_sessions = db.query(NetworkSession).filter(NetworkSession.start_time >= since).count()
    suspicious_sessions = db.query(NetworkSession).filter(
        NetworkSession.start_time >= since,
        NetworkSession.is_suspicious == True
    ).count()
    
    # Traffic volume
    total_bytes_sent = db.query(db.func.sum(NetworkSession.bytes_sent)).filter(
        NetworkSession.start_time >= since
    ).scalar() or 0
    total_bytes_received = db.query(db.func.sum(NetworkSession.bytes_received)).filter(
        NetworkSession.start_time >= since
    ).scalar() or 0
    
    # System health
    error_logs = db.query(SystemLog).filter(
        SystemLog.created_at >= since,
        SystemLog.level.in_([LogLevel.ERROR, LogLevel.CRITICAL])
    ).count()
    
    return {
        "time_period_hours": hours,
        "system_health": {
            "status": "healthy" if error_logs < 10 else "warning" if error_logs < 50 else "critical",
            "error_logs_count": error_logs,
            "uptime_hours": hours  # Simplified
        },
        "devices": {
            "total": total_devices,
            "active": active_devices,
            "inactive": total_devices - active_devices,
            "new_devices": new_devices
        },
        "security": {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "unresolved_alerts": unresolved_alerts,
            "alert_rate_per_hour": round(total_alerts / hours, 2) if hours > 0 else 0
        },
        "network": {
            "total_sessions": total_sessions,
            "suspicious_sessions": suspicious_sessions,
            "total_traffic_bytes": total_bytes_sent + total_bytes_received,
            "traffic_rate_mbps": round(((total_bytes_sent + total_bytes_received) * 8) / (hours * 3600 * 1000000), 2) if hours > 0 else 0
        },
        "generated_at": datetime.now().isoformat()
    }

@router.get("/alerts/timeline")
async def get_alerts_timeline(
    hours: int = Query(24, ge=1, le=168),
    granularity: str = Query("hour", regex="^(hour|day)$"),
    db: Session = Depends(get_db)
):
    """Get alerts timeline for charting"""
    since = datetime.now() - timedelta(hours=hours)
    
    if granularity == "hour":
        # Group by hour
        time_format = "%Y-%m-%d %H:00:00"
        interval = timedelta(hours=1)
    else:
        # Group by day
        time_format = "%Y-%m-%d 00:00:00"
        interval = timedelta(days=1)
    
    # Generate time buckets
    current_time = since.replace(minute=0, second=0, microsecond=0)
    if granularity == "day":
        current_time = current_time.replace(hour=0)
    
    time_buckets = []
    while current_time <= datetime.now():
        time_buckets.append(current_time.strftime(time_format))
        current_time += interval
    
    # Get alert counts by severity and time bucket
    timeline_data = []
    for time_bucket in time_buckets:
        bucket_start = datetime.strptime(time_bucket, time_format)
        bucket_end = bucket_start + interval
        
        severity_counts = {}
        for severity in AlertSeverity:
            count = db.query(Alert).filter(
                Alert.created_at >= bucket_start,
                Alert.created_at < bucket_end,
                Alert.severity == severity
            ).count()
            severity_counts[severity.value] = count
        
        timeline_data.append({
            "time": time_bucket,
            "total": sum(severity_counts.values()),
            "severity_breakdown": severity_counts
        })
    
    return {
        "time_period_hours": hours,
        "granularity": granularity,
        "timeline": timeline_data,
        "generated_at": datetime.now().isoformat()
    }

@router.get("/devices/types")
async def get_device_type_distribution(db: Session = Depends(get_db)):
    """Get device type distribution for pie chart"""
    device_counts = db.query(
        Device.device_type,
        db.func.count(Device.id).label('count')
    ).group_by(Device.device_type).all()
    
    distribution = []
    total = 0
    for device_type, count in device_counts:
        distribution.append({
            "type": device_type.value if device_type else "unknown",
            "count": count,
            "label": device_type.value.replace("_", " ").title() if device_type else "Unknown"
        })
        total += count
    
    # Calculate percentages
    for item in distribution:
        item["percentage"] = round((item["count"] / total * 100), 1) if total > 0 else 0
    
    return {
        "total_devices": total,
        "distribution": distribution,
        "generated_at": datetime.now().isoformat()
    }

@router.get("/network/traffic")
async def get_network_traffic_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get network traffic statistics"""
    since = datetime.now() - timedelta(hours=hours)
    
    # Protocol distribution
    protocol_stats = db.query(
        NetworkSession.protocol,
        db.func.count(NetworkSession.id).label('session_count'),
        db.func.sum(NetworkSession.bytes_sent + NetworkSession.bytes_received).label('total_bytes')
    ).filter(
        NetworkSession.start_time >= since
    ).group_by(NetworkSession.protocol).all()
    
    protocol_distribution = []
    for protocol, session_count, total_bytes in protocol_stats:
        protocol_distribution.append({
            "protocol": protocol,
            "session_count": session_count,
            "total_bytes": total_bytes or 0,
            "percentage": 0  # Will be calculated after
        })
    
    # Calculate percentages
    total_bytes_all = sum(p["total_bytes"] for p in protocol_distribution)
    for item in protocol_distribution:
        item["percentage"] = round((item["total_bytes"] / total_bytes_all * 100), 1) if total_bytes_all > 0 else 0
    
    # Top talkers (by traffic volume)
    top_talkers = db.query(
        NetworkSession.source_ip,
        db.func.sum(NetworkSession.bytes_sent + NetworkSession.bytes_received).label('total_bytes'),
        db.func.count(NetworkSession.id).label('session_count')
    ).filter(
        NetworkSession.start_time >= since
    ).group_by(
        NetworkSession.source_ip
    ).order_by(
        db.func.sum(NetworkSession.bytes_sent + NetworkSession.bytes_received).desc()
    ).limit(10).all()
    
    top_talkers_list = [
        {
            "ip_address": ip,
            "total_bytes": total_bytes or 0,
            "session_count": session_count
        }
        for ip, total_bytes, session_count in top_talkers
    ]
    
    return {
        "time_period_hours": hours,
        "protocol_distribution": protocol_distribution,
        "top_talkers": top_talkers_list,
        "generated_at": datetime.now().isoformat()
    }

@router.get("/security/threats")
async def get_security_threat_summary(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get security threat summary"""
    since = datetime.now() - timedelta(hours=hours)
    
    # Recent critical alerts
    critical_alerts = db.query(Alert).filter(
        Alert.created_at >= since,
        Alert.severity == AlertSeverity.CRITICAL
    ).order_by(Alert.created_at.desc()).limit(10).all()
    
    critical_alerts_list = [
        {
            "id": alert.id,
            "title": alert.title,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "status": alert.status.value,
            "created_at": alert.created_at.isoformat()
        }
        for alert in critical_alerts
    ]
    
    # Threat distribution by type
    alert_counts_by_rule = db.query(
        Alert.rule_id,
        db.func.count(Alert.id).label('count')
    ).filter(
        Alert.created_at >= since
    ).group_by(Alert.rule_id).limit(10).all()
    
    # Suspicious activity indicators
    suspicious_sessions = db.query(NetworkSession).filter(
        NetworkSession.start_time >= since,
        NetworkSession.is_suspicious == True
    ).count()
    
    return {
        "time_period_hours": hours,
        "critical_alerts": critical_alerts_list,
        "suspicious_sessions_count": suspicious_sessions,
        "threat_indicators": {
            "high_entropy_traffic": 0,  # Would need to calculate
            "unusual_protocols": 0,     # Would need to calculate
            "external_connections": 0   # Would need to calculate
        },
        "generated_at": datetime.now().isoformat()
    }

@router.get("/system/health")
async def get_system_health_status(db: Session = Depends(get_db)):
    """Get current system health status"""
    now = datetime.now()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)
    
    # Error log counts
    recent_errors = db.query(SystemLog).filter(
        SystemLog.created_at >= last_hour,
        SystemLog.level.in_([LogLevel.ERROR, LogLevel.CRITICAL])
    ).count()
    
    daily_errors = db.query(SystemLog).filter(
        SystemLog.created_at >= last_24h,
        SystemLog.level.in_([LogLevel.ERROR, LogLevel.CRITICAL])
    ).count()
    
    # System status determination
    if recent_errors == 0 and daily_errors < 5:
        status = "healthy"
        status_message = "System operating normally"
    elif recent_errors < 3 and daily_errors < 20:
        status = "warning"
        status_message = "Minor issues detected"
    else:
        status = "critical"
        status_message = "System issues require attention"
    
    # Component health
    components = db.query(SystemLog.component).distinct().all()
    component_health = {}
    
    for (component,) in components:
        component_errors = db.query(SystemLog).filter(
            SystemLog.component == component,
            SystemLog.created_at >= last_hour,
            SystemLog.level.in_([LogLevel.ERROR, LogLevel.CRITICAL])
        ).count()
        
        component_health[component] = {
            "status": "healthy" if component_errors == 0 else "warning" if component_errors < 3 else "critical",
            "recent_errors": component_errors
        }
    
    return {
        "overall_status": status,
        "status_message": status_message,
        "recent_errors_1h": recent_errors,
        "total_errors_24h": daily_errors,
        "component_health": component_health,
        "last_check": now.isoformat()
    }