from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from core.database import get_db
from models.network_session import NetworkSession
from utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_network_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    hours: Optional[int] = Query(None, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get network sessions with optional filtering"""
    query = db.query(NetworkSession)
    
    if source_ip:
        query = query.filter(NetworkSession.source_ip == source_ip)
    
    if destination_ip:
        query = query.filter(NetworkSession.destination_ip == destination_ip)
    
    if protocol:
        query = query.filter(NetworkSession.protocol == protocol)
    
    if is_suspicious is not None:
        query = query.filter(NetworkSession.is_suspicious == is_suspicious)
    
    if hours:
        since = datetime.now() - timedelta(hours=hours)
        query = query.filter(NetworkSession.start_time >= since)
    
    sessions = query.order_by(NetworkSession.start_time.desc()).offset(skip).limit(limit).all()
    
    return [
        {
            "id": session.id,
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "destination_ip": session.destination_ip,
            "source_port": session.source_port,
            "destination_port": session.destination_port,
            "protocol": session.protocol,
            "bytes_sent": session.bytes_sent,
            "bytes_received": session.bytes_received,
            "packets_sent": session.packets_sent,
            "packets_received": session.packets_received,
            "duration": session.duration,
            "is_encrypted": session.is_encrypted,
            "is_suspicious": session.is_suspicious,
            "device_id": session.device_id,
            "start_time": session.start_time.isoformat() if session.start_time else None,
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "created_at": session.created_at.isoformat()
        }
        for session in sessions
    ]

@router.get("/{session_id}")
async def get_network_session(session_id: int, db: Session = Depends(get_db)):
    """Get specific network session by ID"""
    session = db.query(NetworkSession).filter(NetworkSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Network session not found")
    
    return {
        "id": session.id,
        "session_id": session.session_id,
        "source_ip": session.source_ip,
        "destination_ip": session.destination_ip,
        "source_port": session.source_port,
        "destination_port": session.destination_port,
        "protocol": session.protocol,
        "bytes_sent": session.bytes_sent,
        "bytes_received": session.bytes_received,
        "packets_sent": session.packets_sent,
        "packets_received": session.packets_received,
        "duration": session.duration,
        "is_encrypted": session.is_encrypted,
        "is_suspicious": session.is_suspicious,
        "device_id": session.device_id,
        "start_time": session.start_time.isoformat() if session.start_time else None,
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "created_at": session.created_at.isoformat(),
        "device": {
            "id": session.device.id,
            "mac_address": session.device.mac_address,
            "ip_address": session.device.ip_address,
            "hostname": session.device.hostname,
            "device_type": session.device.device_type.value if session.device.device_type else None
        } if session.device else None
    }

@router.get("/stats/summary")
async def get_session_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get network session statistics"""
    since = datetime.now() - timedelta(hours=hours)
    
    total_sessions = db.query(NetworkSession).filter(NetworkSession.start_time >= since).count()
    suspicious_sessions = db.query(NetworkSession).filter(
        NetworkSession.start_time >= since,
        NetworkSession.is_suspicious == True
    ).count()
    encrypted_sessions = db.query(NetworkSession).filter(
        NetworkSession.start_time >= since,
        NetworkSession.is_encrypted == True
    ).count()
    
    # Protocol breakdown
    protocols = db.query(NetworkSession.protocol).filter(NetworkSession.start_time >= since).distinct().all()
    protocol_counts = {}
    for (protocol,) in protocols:
        count = db.query(NetworkSession).filter(
            NetworkSession.protocol == protocol,
            NetworkSession.start_time >= since
        ).count()
        protocol_counts[protocol] = count
    
    # Traffic volume
    total_bytes_sent = db.query(db.func.sum(NetworkSession.bytes_sent)).filter(NetworkSession.start_time >= since).scalar() or 0
    total_bytes_received = db.query(db.func.sum(NetworkSession.bytes_received)).filter(NetworkSession.start_time >= since).scalar() or 0
    
    return {
        "time_period_hours": hours,
        "total_sessions": total_sessions,
        "suspicious_sessions": suspicious_sessions,
        "encrypted_sessions": encrypted_sessions,
        "protocol_breakdown": protocol_counts,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_received": total_bytes_received,
        "total_traffic_bytes": total_bytes_sent + total_bytes_received,
        "generated_at": datetime.now().isoformat()
    }

@router.get("/top/talkers")
async def get_top_talkers(
    limit: int = Query(10, ge=1, le=100),
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get top network talkers by traffic volume"""
    since = datetime.now() - timedelta(hours=hours)
    
    # Query for top source IPs by bytes sent
    top_senders = db.query(
        NetworkSession.source_ip,
        db.func.sum(NetworkSession.bytes_sent).label('total_bytes_sent'),
        db.func.count(NetworkSession.id).label('session_count')
    ).filter(
        NetworkSession.start_time >= since
    ).group_by(
        NetworkSession.source_ip
    ).order_by(
        db.func.sum(NetworkSession.bytes_sent).desc()
    ).limit(limit).all()
    
    # Query for top destination IPs by bytes received
    top_receivers = db.query(
        NetworkSession.destination_ip,
        db.func.sum(NetworkSession.bytes_received).label('total_bytes_received'),
        db.func.count(NetworkSession.id).label('session_count')
    ).filter(
        NetworkSession.start_time >= since
    ).group_by(
        NetworkSession.destination_ip
    ).order_by(
        db.func.sum(NetworkSession.bytes_received).desc()
    ).limit(limit).all()
    
    return {
        "time_period_hours": hours,
        "top_senders": [
            {
                "ip_address": ip,
                "total_bytes_sent": bytes_sent,
                "session_count": count
            }
            for ip, bytes_sent, count in top_senders
        ],
        "top_receivers": [
            {
                "ip_address": ip,
                "total_bytes_received": bytes_received,
                "session_count": count
            }
            for ip, bytes_received, count in top_receivers
        ],
        "generated_at": datetime.now().isoformat()
    }