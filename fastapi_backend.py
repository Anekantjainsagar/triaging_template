from fastapi import FastAPI
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Import routers
from routes.search_alert import router as search_alert_router
from routes.analyzer_router import router as analyzer_router
from routes.predictions_router import router as predictions_router

load_dotenv()


# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown tasks"""
    # Startup
    print("=" * 80)
    print("🚀 Starting Security Alert Management API")
    print("=" * 80)
    print("\n📊 Loading data...")

    # Load search alert data
    try:
        from routes.search_alert import get_tracker_data

        get_tracker_data(force_reload=True)
        print("✅ Search alert data loaded successfully!")
    except Exception as e:
        print(f"⚠️ Warning: Could not load search alert data: {str(e)}")

    # Load analyzer data
    try:
        from routes.analyzer_router import get_analyzers

        get_analyzers(force_reload=True)
        print("✅ SOC analyzer data loaded successfully!")
    except Exception as e:
        print(f"⚠️ Warning: Could not load analyzer data: {str(e)}")

    # Initialize predictions analyzer
    try:
        print("✅ Predictions API initialized and ready!")
    except Exception as e:
        print(f"⚠️ Warning: Could not initialize predictions API: {str(e)}")

    print("\n📚 API Documentation available at:")
    print("  - Swagger UI: http://localhost:8000/docs")
    print("  - ReDoc: http://localhost:8000/redoc")
    print("\n🔌 Available API Routes:")
    print("  - /search-alert/* (Search Alert endpoints)")
    print("  - /analyzer/* (SOC Analyzer endpoints)")
    print("  - /predictions/* (Predictions & MITRE Analysis endpoints)")
    print("=" * 80)

    yield  # Application runs here

    # Shutdown
    print("\n🛑 Shutting down Security Alert Management API...")


# Initialize FastAPI app
app = FastAPI(
    title="Security Alert Management & Threat Intelligence API",
    description="Comprehensive API for managing security alerts, incidents, SOC operations, and threat investigations with AI-powered MITRE ATT&CK analysis",
    version="3.0.0",
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
app.include_router(analyzer_router, prefix="/analyzer", tags=["SOC Analyzer"])
app.include_router(
    predictions_router, prefix="/predictions", tags=["Predictions & MITRE"]
)


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Security Alert Management & Threat Intelligence API",
        "version": "3.0.0",
        "status": "running",
        "documentation": {"swagger_ui": "/docs", "redoc": "/redoc"},
        "available_routes": {
            "search_alerts": "/search-alert",
            "soc_analyzer": "/analyzer",
            "predictions": "/predictions",
        },
        "features": [
            "Search Alert Management",
            "SOC Analysis & Rule Suggestions",
            "Threat Investigation with MITRE ATT&CK",
            "True/False Positive Classification",
            "Batch Analysis & Comparison",
            "Defensive Recommendations",
        ],
    }


@app.get("/health", tags=["System"])
async def system_health():
    """System-wide health check"""
    return {
        "status": "healthy",
        "service": "Security Alert Management & Threat Intelligence API",
        "version": "3.0.0",
    }


# Run with: uvicorn fastapi_backend:app --reload --host 0.0.0.0 --port 8000
# Modified startup
if __name__ == "__main__":
    import uvicorn

    try:
        print("\n🌐 Starting server on http://localhost:8000")
        print("📖 API Docs will be at http://localhost:8000/docs\n")

        uvicorn.run(
            "fastapi_backend:app",
            host="127.0.0.1",  # Changed from 0.0.0.0
            port=8000,
            reload=True,
            reload_dirs=["routes", "backend"],
            log_level="info",
        )
    except OSError as e:
        if "address already in use" in str(e).lower():
            print("\n❌ ERROR: Port 8000 is already in use!")
            print("Kill the existing process or use a different port:")
            print("   uvicorn fastapi_backend:app --reload --port 8001")
        else:
            raise
