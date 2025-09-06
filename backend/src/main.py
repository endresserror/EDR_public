from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import uvicorn

from core.config import settings
from core.database import init_db
from api.routers import devices, alerts, sessions, rules, logs, dashboard
from services.network_monitor import NetworkMonitor
from services.threat_engine import ThreatEngine
from utils.logger import setup_logger

logger = setup_logger(__name__)

network_monitor = None
threat_engine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global network_monitor, threat_engine
    
    logger.info("Starting IoT EDR System...")
    
    init_db()
    
    threat_engine = ThreatEngine()
    await threat_engine.load_rules()
    
    network_monitor = NetworkMonitor(threat_engine)
    monitor_task = asyncio.create_task(network_monitor.start_monitoring())
    
    logger.info("IoT EDR System started successfully")
    
    yield
    
    logger.info("Shutting down IoT EDR System...")
    if network_monitor:
        await network_monitor.stop_monitoring()
    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices.router, prefix="/api/v1/devices", tags=["devices"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(sessions.router, prefix="/api/v1/sessions", tags=["sessions"])
app.include_router(rules.router, prefix="/api/v1/rules", tags=["rules"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["logs"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])

@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.app_name} v{settings.version}"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.version,
        "network_monitor_active": network_monitor is not None and network_monitor.is_running
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.web_dashboard_host,
        port=settings.web_dashboard_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )