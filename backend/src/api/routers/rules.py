from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from core.database import get_db
from models.threat_rule import ThreatRule, ThreatRuleType
from utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_threat_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    rule_type: Optional[ThreatRuleType] = None,
    is_enabled: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Get threat detection rules"""
    query = db.query(ThreatRule)
    
    if rule_type:
        query = query.filter(ThreatRule.rule_type == rule_type)
    
    if is_enabled is not None:
        query = query.filter(ThreatRule.is_enabled == is_enabled)
    
    rules = query.order_by(ThreatRule.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "rule_type": rule.rule_type.value if rule.rule_type else None,
            "severity": rule.severity,
            "is_enabled": rule.is_enabled,
            "confidence": rule.confidence,
            "tags": rule.tags,
            "mitre_attack_id": rule.mitre_attack_id,
            "created_by": rule.created_by,
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() if rule.updated_at else None
        }
        for rule in rules
    ]

@router.get("/{rule_id}")
async def get_threat_rule(rule_id: int, db: Session = Depends(get_db)):
    """Get specific threat rule by ID"""
    rule = db.query(ThreatRule).filter(ThreatRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Threat rule not found")
    
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "rule_type": rule.rule_type.value if rule.rule_type else None,
        "rule_content": rule.rule_content,
        "severity": rule.severity,
        "is_enabled": rule.is_enabled,
        "confidence": rule.confidence,
        "tags": rule.tags,
        "mitre_attack_id": rule.mitre_attack_id,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None
    }

@router.post("/")
async def create_threat_rule(
    name: str,
    description: str,
    rule_type: ThreatRuleType,
    rule_content: str,
    severity: str = "medium",
    confidence: int = 50,
    tags: Optional[str] = None,
    mitre_attack_id: Optional[str] = None,
    created_by: str = "system",
    db: Session = Depends(get_db)
):
    """Create new threat detection rule"""
    # Check if rule name already exists
    existing_rule = db.query(ThreatRule).filter(ThreatRule.name == name).first()
    if existing_rule:
        raise HTTPException(status_code=400, detail="Rule with this name already exists")
    
    rule = ThreatRule(
        name=name,
        description=description,
        rule_type=rule_type,
        rule_content=rule_content,
        severity=severity,
        confidence=confidence,
        tags=tags,
        mitre_attack_id=mitre_attack_id,
        created_by=created_by
    )
    
    db.add(rule)
    db.commit()
    db.refresh(rule)
    
    logger.info(f"New threat rule created: {rule.name} by {created_by}")
    
    return {
        "id": rule.id,
        "message": "Threat rule created successfully"
    }

@router.put("/{rule_id}")
async def update_threat_rule(
    rule_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    rule_content: Optional[str] = None,
    severity: Optional[str] = None,
    is_enabled: Optional[bool] = None,
    confidence: Optional[int] = None,
    tags: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Update threat detection rule"""
    rule = db.query(ThreatRule).filter(ThreatRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Threat rule not found")
    
    if name is not None:
        # Check if new name conflicts with existing rule
        existing_rule = db.query(ThreatRule).filter(
            ThreatRule.name == name,
            ThreatRule.id != rule_id
        ).first()
        if existing_rule:
            raise HTTPException(status_code=400, detail="Rule with this name already exists")
        rule.name = name
    
    if description is not None:
        rule.description = description
    
    if rule_content is not None:
        rule.rule_content = rule_content
    
    if severity is not None:
        rule.severity = severity
    
    if is_enabled is not None:
        rule.is_enabled = is_enabled
    
    if confidence is not None:
        if not 0 <= confidence <= 100:
            raise HTTPException(status_code=400, detail="Confidence must be between 0 and 100")
        rule.confidence = confidence
    
    if tags is not None:
        rule.tags = tags
    
    rule.updated_at = datetime.now()
    db.commit()
    
    logger.info(f"Threat rule {rule_id} updated")
    
    return {"message": "Threat rule updated successfully"}

@router.delete("/{rule_id}")
async def delete_threat_rule(rule_id: int, db: Session = Depends(get_db)):
    """Delete threat detection rule"""
    rule = db.query(ThreatRule).filter(ThreatRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Threat rule not found")
    
    db.delete(rule)
    db.commit()
    
    logger.info(f"Threat rule {rule_id} deleted")
    
    return {"message": "Threat rule deleted successfully"}

@router.put("/{rule_id}/enable")
async def enable_threat_rule(rule_id: int, db: Session = Depends(get_db)):
    """Enable threat detection rule"""
    rule = db.query(ThreatRule).filter(ThreatRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Threat rule not found")
    
    rule.is_enabled = True
    rule.updated_at = datetime.now()
    db.commit()
    
    logger.info(f"Threat rule {rule_id} enabled")
    
    return {"message": "Threat rule enabled successfully"}

@router.put("/{rule_id}/disable")
async def disable_threat_rule(rule_id: int, db: Session = Depends(get_db)):
    """Disable threat detection rule"""
    rule = db.query(ThreatRule).filter(ThreatRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Threat rule not found")
    
    rule.is_enabled = False
    rule.updated_at = datetime.now()
    db.commit()
    
    logger.info(f"Threat rule {rule_id} disabled")
    
    return {"message": "Threat rule disabled successfully"}

@router.get("/stats/summary")
async def get_rule_stats(db: Session = Depends(get_db)):
    """Get threat rule statistics"""
    total_rules = db.query(ThreatRule).count()
    enabled_rules = db.query(ThreatRule).filter(ThreatRule.is_enabled == True).count()
    
    # Rule type breakdown
    type_counts = {}
    for rule_type in ThreatRuleType:
        count = db.query(ThreatRule).filter(ThreatRule.rule_type == rule_type).count()
        if count > 0:
            type_counts[rule_type.value] = count
    
    # Severity breakdown
    severity_counts = db.query(ThreatRule.severity, db.func.count(ThreatRule.id)).group_by(ThreatRule.severity).all()
    severity_breakdown = {severity: count for severity, count in severity_counts}
    
    return {
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "disabled_rules": total_rules - enabled_rules,
        "rule_type_breakdown": type_counts,
        "severity_breakdown": severity_breakdown,
        "generated_at": datetime.now().isoformat()
    }