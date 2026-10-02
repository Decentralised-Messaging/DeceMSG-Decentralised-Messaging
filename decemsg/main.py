"""DeceMSG main application entry point."""
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from decemsg.core.database import init_db, close_db
from decemsg.core.config import get_config
from decemsg.core.rate_limiter import limiter, rate_limit_exceeded_handler
from decemsg.api import (
    auth_router,
    users_router,
    avatars_router,
    chats_router,
    messages_router,
    admin_router,
    websocket_router,
)
from decemsg.federation import router as federation_router
from decemsg.federation.auth_middleware import FederationAuthMiddleware


# Determine UI directory
_ui_dir = Path(__file__).parent / "ui"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await init_db()
    
    # Create data directories
    data_dir = Path("./data")
    data_dir.mkdir(exist_ok=True)
    (data_dir / "uploads").mkdir(exist_ok=True)
    (data_dir / "backups").mkdir(exist_ok=True)
    
    yield
    
    # Shutdown
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()
    
    app = FastAPI(
        title=config.server.title,
        description="Decentralized Messaging Platform API",
        version="0.1.0",
        lifespan=lifespan,
    )
    
    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; connect-src 'self' ws: wss:; "
            "font-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self';",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
        )
        return response

    # Add rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    
    # Federation authentication must wrap every non-public federation route.
    app.add_middleware(FederationAuthMiddleware)

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict this
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(avatars_router)
    app.include_router(chats_router)
    app.include_router(messages_router)
    app.include_router(admin_router)
    app.include_router(websocket_router)
    app.include_router(federation_router)
    
    # Root redirect to UI
    @app.get("/")
    async def root():
        """Redirect to the web UI."""
        return RedirectResponse(url="/ui")
    
    # Serve UI files
    @app.get("/ui")
    async def ui_index():
        """Serve the main UI page."""
        return FileResponse(str(_ui_dir / "index.html"))
    
    @app.get("/ui/{filename}")
    async def ui_static(filename: str):
        """Serve UI static files."""
        file_path = _ui_dir / filename
        if file_path.exists():
            return FileResponse(str(file_path))
        
        # Try to serve from root
        root_path = Path(filename)
        if root_path.exists():
            return FileResponse(str(root_path))
        
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="File not found")
    
    # Health check
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "version": "0.1.0"}
    
    # Serve uploaded files
    uploads_dir = Path("./data/uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/uploads", StaticFiles(directory=str(uploads_dir)), name="uploads")
    app.mount("/ui/styles.css", StaticFiles(directory=str(_ui_dir), html=False), name="styles")
    app.mount("/ui/app.js", StaticFiles(directory=str(_ui_dir), html=False), name="app_js")
    app.mount("/ui/manifest.json", StaticFiles(directory=str(_ui_dir), html=False), name="manifest")
    app.mount("/ui/sw.js", StaticFiles(directory=str(_ui_dir), html=False), name="sw")
    
    return app


# Create app instance
app = create_app()


def run_cli():
    """CLI entry point for running the server."""
    import uvicorn
    
    config = get_config()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    DeceMSG Server                             ║
║           Decentralized Messaging Platform                    ║
╠══════════════════════════════════════════════════════════════╣
║  Domain:     {:<42}║
║  API:        http://{}:{}                                  ║
║  WebSocket:  ws://{}:{}/ws                                 ║
╚══════════════════════════════════════════════════════════════╝
    """.format(config.server.domain, config.server.host, config.server.port, config.server.host, config.server.port))
    
    uvicorn.run(
        "decemsg.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    run_cli()
