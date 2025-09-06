from sqlalchemy import Column, Integer, String, DateTime, Boolean, BigInteger, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from core.database import Base

class NetworkSession(Base):
    __tablename__ = "network_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True)
    source_ip = Column(String(15), nullable=False)
    destination_ip = Column(String(15), nullable=False)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10), nullable=False)
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)
    packets_sent = Column(Integer, default=0)
    packets_received = Column(Integer, default=0)
    duration = Column(Integer)
    is_encrypted = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False)
    device_id = Column(Integer, ForeignKey("devices.id"))
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    
    device = relationship("Device")