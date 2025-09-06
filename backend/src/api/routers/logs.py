from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from core.database import get_db
from models.system_log import SystemLog, LogLevel
from utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_system_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    level: Optional[LogLevel] = None,
    component: Optional[str] = None,
    hours: Optional[int] = Query(None, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get system logs with optional filtering"""
    query = db.query(SystemLog)
    
    if level:
        query = query.filter(SystemLog.level == level)
    
    if component:
        query = query.filter(SystemLog.component == component)
    
    if hours:
        since = datetime.now() - timedelta(hours=hours)
        query = query.filter(SystemLog.created_at >= since)
    
    logs = query.order_by(SystemLog.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        {
            "id": log.id,
            "level": log.level.value,
            "component": log.component,
            "message": log.message,
            "details": log.details,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "created_at": log.created_at.isoformat()
        }
        for log in logs
    ]

@router.get("/{log_id}")
async def get_system_log(log_id: int, db: Session = Depends(get_db)):
    """Get specific system log by ID"""
    log = db.query(SystemLog).filter(SystemLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="System log not found")
    
    return {
        "id": log.id,
        "level": log.level.value,
        "component": log.component,
        "message": log.message,
        "details": log.details,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "created_at": log.created_at.isoformat()
    }

@router.post("/")
async def create_system_log(
    level: LogLevel,
    component: str,
    message: str,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Create new system log entry"""
    log = SystemLog(
        level=level,
        component=component,
        message=message,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    db.add(log)
    db.commit()
    db.refresh(log)
    
    return {
        "id": log.id,
        "message": "System log created successfully"
    }

@router.get("/stats/summary")
async def get_log_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get system log statistics"""
    since = datetime.now() - timedelta(hours=hours)
    
    total_logs = db.query(SystemLog).filter(SystemLog.created_at >= since).count()
    
    # Level breakdown
    level_counts = {}
    for level in LogLevel:
        count = db.query(SystemLog).filter(
            SystemLog.level == level,
            SystemLog.created_at >= since
        ).count()
        level_counts[level.value] = count
    
    # Component breakdown
    component_counts = db.query(
        SystemLog.component,
        db.func.count(SystemLog.id)
    ).filter(
        SystemLog.created_at >= since
    ).group_by(
        SystemLog.component
    ).all()
    
    component_breakdown = {component: count for component, count in component_counts}
    
    # Recent critical/error logs
    critical_logs = db.query(SystemLog).filter(
        SystemLog.level.in_([LogLevel.CRITICAL, LogLevel.ERROR]),
        SystemLog.created_at >= since
    ).order_by(SystemLog.created_at.desc()).limit(10).all()
    
    recent_critical = [
        {
            "id": log.id,
            "level": log.level.value,
            "component": log.component,
            "message": log.message,
            "created_at": log.created_at.isoformat()
        }
        for log in critical_logs
    ]
    
    return {
        "time_period_hours": hours,
        "total_logs": total_logs,
        "level_breakdown": level_counts,
        "component_breakdown": component_breakdown,
        "recent_critical_logs": recent_critical,
        "generated_at": datetime.now().isoformat()
    }

@router.delete("/cleanup")
async def cleanup_old_logs(
    days: int = Query(30, ge=1, le=365),
    dry_run: bool = Query(False),
    db: Session = Depends(get_db)
):
    """Clean up old system logs"""
    cutoff_date = datetime.now() - timedelta(days=days)
    
    logs_to_delete = db.query(SystemLog).filter(SystemLog.created_at < cutoff_date)
    count = logs_to_delete.count()
    
    if not dry_run:
        logs_to_delete.delete()
        db.commit()
        logger.info(f"Deleted {count} old system logs older than {days} days")
        return {"message": f"Deleted {count} old system logs", "deleted_count": count}
    else:
        return {"message": f"Would delete {count} old system logs", "would_delete_count": count}

@router.get("/components/list")
async def get_log_components(db: Session = Depends(get_db)):
    """Get list of all log components"""
    components = db.query(SystemLog.component).distinct().all()
    
    return {
        "components": [component[0] for component in components],
        "generated_at": datetime.now().isoformat()
    }

@router.get("/export/csv")
async def export_logs_csv(
    level: Optional[LogLevel] = None,
    component: Optional[str] = None,
    hours: Optional[int] = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Export system logs as CSV"""
    from fastapi.responses import StreamingResponse
    import csv
    import io
    
    query = db.query(SystemLog)
    
    if level:
        query = query.filter(SystemLog.level == level)
    
    if component:
        query = query.filter(SystemLog.component == component)
    
    if hours:
        since = datetime.now() - timedelta(hours=hours)
        query = query.filter(SystemLog.created_at >= since)
    
    logs = query.order_by(SystemLog.created_at.desc()).all()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Level', 'Component', 'Message', 'Details', 
        'IP Address', 'User Agent', 'Created At'
    ])
    
    # Write data
    for log in logs:
        writer.writerow([
            log.id,
            log.level.value,
            log.component,
            log.message,
            log.details or '',
            log.ip_address or '',
            log.user_agent or '',
            log.created_at.isoformat()
        ])
    
    output.seek(0)
    
    filename = f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/export/json")
async def export_logs_json(
    level: Optional[LogLevel] = None,
    component: Optional[str] = None,
    hours: Optional[int] = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Export system logs as JSON"""
    from fastapi.responses import StreamingResponse
    import json
    import io
    
    query = db.query(SystemLog)
    
    if level:
        query = query.filter(SystemLog.level == level)
    
    if component:
        query = query.filter(SystemLog.component == component)
    
    if hours:
        since = datetime.now() - timedelta(hours=hours)
        query = query.filter(SystemLog.created_at >= since)
    
    logs = query.order_by(SystemLog.created_at.desc()).all()
    
    # Create JSON content
    log_data = []
    for log in logs:
        log_data.append({
            'id': log.id,
            'level': log.level.value,
            'component': log.component,
            'message': log.message,
            'details': log.details,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'created_at': log.created_at.isoformat()
        })
    
    export_data = {
        'export_metadata': {
            'exported_at': datetime.now().isoformat(),
            'total_records': len(log_data),
            'filters': {
                'level': level.value if level else None,
                'component': component,
                'hours': hours
            }
        },
        'logs': log_data
    }
    
    json_content = json.dumps(export_data, indent=2)
    
    filename = f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    return StreamingResponse(
        io.StringIO(json_content),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )