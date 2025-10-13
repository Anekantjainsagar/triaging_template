from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import routers - make sure the path matches your file structure
from routes.search_alert import router as search_alert_router


# Lifespan event handler (replaces on_event)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown tasks"""
    # Startup
    print("=" * 80)
    print("🚀 Starting Security Alert Management API")
    print("=" * 80)
    print("\n📊 Loading tracker data...")

    # Load data on startup
    try:
        from routes.search_alert import get_tracker_data

        get_tracker_data(force_reload=True)
        print("✅ Data loaded successfully!")
    except Exception as e:
        print(f"⚠️ Warning: Could not load data on startup: {str(e)}")

    print("\n📚 API Documentation available at:")
    print("  - Swagger UI: http://localhost:8000/docs")
    print("  - ReDoc: http://localhost:8000/redoc")
    print("\n📌 Available API Routes:")
    print("  - /search-alert/* (Search Alert endpoints)")
    print("=" * 80)

    yield  # Application runs here

    # Shutdown
    print("\n🛑 Shutting down Security Alert Management API...")


# Initialize FastAPI app with lifespan (ONLY ONCE!)
app = FastAPI(
    title="Security Alert Management API",
    description="Comprehensive API for managing security alerts, incidents, and SOC operations",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers with prefixes
app.include_router(search_alert_router, prefix="/search-alert", tags=["Search Alerts"])

# You can add more routers here as you build more features
# app.include_router(incident_router, prefix="/incidents", tags=["Incidents"])
# app.include_router(analytics_router, prefix="/analytics", tags=["Analytics"])
# app.include_router(reports_router, prefix="/reports", tags=["Reports"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Security Alert Management API",
        "version": "2.0.0",
        "status": "running",
        "documentation": {"swagger_ui": "/docs", "redoc": "/redoc"},
        "available_routes": {
            "search_alerts": "/search-alert",
        },
    }


@app.get("/health", tags=["System"])
async def system_health():
    """System-wide health check"""
    return {
        "status": "healthy",
        "service": "Security Alert Management API",
        "version": "2.0.0",
    }


# Run with: uvicorn fastapi_backend:app --reload --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "fastapi_backend:app", host="0.0.0.0", port=8000, reload=True, log_level="info"
    )
