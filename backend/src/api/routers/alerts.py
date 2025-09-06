from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from core.database import get_db
from models.alert import Alert, AlertSeverity, AlertStatus
from utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    hours: Optional[int] = Query(None, ge=1, le=720),
    db: Session = Depends(get_db)
):
    """Get alerts with optional filtering"""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if status:
        query = query.filter(Alert.status == status)
    
    if hours:
        since = datetime.now() - timedelta(hours=hours)
        query = query.filter(Alert.created_at >= since)
    
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "source_port": alert.source_port,
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "device_id": alert.device_id,
            "rule_id": alert.rule_id,
            "is_acknowledged": alert.is_acknowledged,
            "acknowledged_by": alert.acknowledged_by,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "created_at": alert.created_at.isoformat(),
            "updated_at": alert.updated_at.isoformat()
        }
        for alert in alerts
    ]

@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get specific alert by ID"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "source_port": alert.source_port,
        "destination_port": alert.destination_port,
        "protocol": alert.protocol,
        "device_id": alert.device_id,
        "rule_id": alert.rule_id,
        "raw_data": alert.raw_data,
        "is_acknowledged": alert.is_acknowledged,
        "acknowledged_by": alert.acknowledged_by,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "created_at": alert.created_at.isoformat(),
        "updated_at": alert.updated_at.isoformat(),
        "device": {
            "id": alert.device.id,
            "mac_address": alert.device.mac_address,
            "ip_address": alert.device.ip_address,
            "hostname": alert.device.hostname,
            "device_type": alert.device.device_type.value if alert.device.device_type else None
        } if alert.device else None,
        "rule": {
            "id": alert.rule.id,
            "name": alert.rule.name,
            "rule_type": alert.rule.rule_type.value if alert.rule.rule_type else None
        } if alert.rule else None
    }

@router.put("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    acknowledged_by: str = "system",
    db: Session = Depends(get_db)
):
    """Acknowledge an alert"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_acknowledged = True
    alert.acknowledged_by = acknowledged_by
    alert.acknowledged_at = datetime.now()
    alert.status = AlertStatus.ACKNOWLEDGED
    
    db.commit()
    
    logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
    
    return {"message": "Alert acknowledged successfully"}

@router.put("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    resolved_by: str = "system",
    db: Session = Depends(get_db)
):
    """Resolve an alert"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = AlertStatus.RESOLVED
    alert.acknowledged_by = resolved_by
    alert.acknowledged_at = datetime.now()
    
    db.commit()
    
    logger.info(f"Alert {alert_id} resolved by {resolved_by}")
    
    return {"message": "Alert resolved successfully"}

@router.put("/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: int,
    marked_by: str = "system",
    db: Session = Depends(get_db)
):
    """Mark alert as false positive"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = AlertStatus.FALSE_POSITIVE
    alert.acknowledged_by = marked_by
    alert.acknowledged_at = datetime.now()
    
    db.commit()
    
    logger.info(f"Alert {alert_id} marked as false positive by {marked_by}")
    
    return {"message": "Alert marked as false positive"}

@router.get("/stats/summary")
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db)
):
    """Get alert statistics summary"""
    since = datetime.now() - timedelta(hours=hours)
    
    total_alerts = db.query(Alert).filter(Alert.created_at >= since).count()
    
    severity_counts = {}
    for severity in AlertSeverity:
        count = db.query(Alert).filter(
            Alert.severity == severity,
            Alert.created_at >= since
        ).count()
        severity_counts[severity.value] = count
    
    status_counts = {}
    for status in AlertStatus:
        count = db.query(Alert).filter(
            Alert.status == status,
            Alert.created_at >= since
        ).count()
        status_counts[status.value] = count
    
    return {
        "time_period_hours": hours,
        "total_alerts": total_alerts,
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "generated_at": datetime.now().isoformat()
    }