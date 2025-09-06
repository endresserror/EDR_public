from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Enum
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from core.database import Base

class ThreatRuleType(PyEnum):
    SIGNATURE = "signature"
    ANOMALY = "anomaly"
    BEHAVIORAL = "behavioral"
    REPUTATION = "reputation"
    CUSTOM = "custom"

class ThreatRule(Base):
    __tablename__ = "threat_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    rule_type = Column(Enum(ThreatRuleType), nullable=False)
    rule_content = Column(Text, nullable=False)
    severity = Column(String(20), default="medium")
    is_enabled = Column(Boolean, default=True)
    confidence = Column(Integer, default=50)
    tags = Column(Text)
    mitre_attack_id = Column(String(20))
    created_by = Column(String(100))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())