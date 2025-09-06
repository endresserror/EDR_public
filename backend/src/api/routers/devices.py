from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from core.database import get_db
from models.device import Device, DeviceType
from utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_type: Optional[DeviceType] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Get all discovered devices"""
    query = db.query(Device)
    
    if device_type:
        query = query.filter(Device.device_type == device_type)
    
    if is_active is not None:
        query = query.filter(Device.is_active == is_active)
    
    devices = query.order_by(Device.last_seen.desc()).offset(skip).limit(limit).all()
    
    return [
        {
            "id": device.id,
            "mac_address": device.mac_address,
            "ip_address": device.ip_address,
            "hostname": device.hostname,
            "device_type": device.device_type.value if device.device_type else None,
            "manufacturer": device.manufacturer,
            "model": device.model,
            "firmware_version": device.firmware_version,
            "is_active": device.is_active,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "first_seen": device.first_seen.isoformat() if device.first_seen else None,
            "trust_score": device.trust_score,
            "description": device.description,
            "created_at": device.created_at.isoformat(),
            "updated_at": device.updated_at.isoformat()
        }
        for device in devices
    ]

@router.get("/{device_id}")
async def get_device(device_id: int, db: Session = Depends(get_db)):
    """Get specific device by ID"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return {
        "id": device.id,
        "mac_address": device.mac_address,
        "ip_address": device.ip_address,
        "hostname": device.hostname,
        "device_type": device.device_type.value if device.device_type else None,
        "manufacturer": device.manufacturer,
        "model": device.model,
        "firmware_version": device.firmware_version,
        "is_active": device.is_active,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "trust_score": device.trust_score,
        "description": device.description,
        "created_at": device.created_at.isoformat(),
        "updated_at": device.updated_at.isoformat()
    }

@router.put("/{device_id}")
async def update_device(
    device_id: int,
    device_type: Optional[DeviceType] = None,
    description: Optional[str] = None,
    trust_score: Optional[float] = None,
    db: Session = Depends(get_db)
):
    """Update device information"""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if device_type is not None:
        device.device_type = device_type
    
    if description is not None:
        device.description = description
    
    if trust_score is not None:
        if not 0.0 <= trust_score <= 1.0:
            raise HTTPException(status_code=400, detail="Trust score must be between 0.0 and 1.0")
        device.trust_score = trust_score
    
    device.updated_at = datetime.now()
    db.commit()
    
    logger.info(f"Device {device_id} updated")
    
    return {"message": "Device updated successfully"}

@router.get("/stats/summary")
async def get_device_stats(db: Session = Depends(get_db)):
    """Get device statistics summary"""
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.is_active == True).count()
    
    # Device type breakdown
    type_counts = {}
    for device_type in DeviceType:
        count = db.query(Device).filter(Device.device_type == device_type).count()
        if count > 0:
            type_counts[device_type.value] = count
    
    # Recently seen devices (last 24 hours)
    since_24h = datetime.now() - timedelta(hours=24)
    recent_devices = db.query(Device).filter(Device.last_seen >= since_24h).count()
    
    # New devices (first seen in last 24 hours)
    new_devices = db.query(Device).filter(Device.first_seen >= since_24h).count()
    
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "inactive_devices": total_devices - active_devices,
        "device_type_breakdown": type_counts,
        "recent_activity_24h": recent_devices,
        "new_devices_24h": new_devices,
        "generated_at": datetime.now().isoformat()
    }

@router.get("/activity/timeline")
async def get_device_activity_timeline(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get device activity timeline"""
    since = datetime.now() - timedelta(hours=hours)
    
    # Get devices by activity time
    devices = db.query(Device).filter(Device.last_seen >= since).order_by(Device.last_seen.desc()).all()
    
    timeline = []
    for device in devices:
        timeline.append({
            "device_id": device.id,
            "mac_address": device.mac_address,
            "ip_address": device.ip_address,
            "hostname": device.hostname,
            "device_type": device.device_type.value if device.device_type else None,
            "manufacturer": device.manufacturer,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "is_active": device.is_active
        })
    
    return {
        "time_period_hours": hours,
        "device_count": len(timeline),
        "timeline": timeline,
        "generated_at": datetime.now().isoformat()
    }