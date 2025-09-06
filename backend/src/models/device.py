from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, Enum
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from core.database import Base

class DeviceType(PyEnum):
    UNKNOWN = "unknown"
    CAMERA = "camera"
    SMART_SPEAKER = "smart_speaker"
    SMART_TV = "smart_tv"
    SMART_PLUG = "smart_plug"
    SENSOR = "sensor"
    THERMOSTAT = "thermostat"
    LIGHT_BULB = "light_bulb"
    ROUTER = "router"
    HUB = "hub"
    PRINTER = "printer"
    NAS = "nas"

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String(17), unique=True, index=True, nullable=False)
    ip_address = Column(String(15), index=True)
    hostname = Column(String(255))
    device_type = Column(Enum(DeviceType), default=DeviceType.UNKNOWN)
    manufacturer = Column(String(255))
    model = Column(String(255))
    firmware_version = Column(String(100))
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=func.now())
    first_seen = Column(DateTime, default=func.now())
    trust_score = Column(Float, default=0.5)
    description = Column(Text)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())