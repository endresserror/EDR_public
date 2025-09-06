from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from core.database import Base

class LogLevel(PyEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    level = Column(Enum(LogLevel), nullable=False)
    component = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(Text)
    ip_address = Column(String(15))
    user_agent = Column(String(500))
    created_at = Column(DateTime, default=func.now())