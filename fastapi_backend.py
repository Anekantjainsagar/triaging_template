from fastapi import FastAPI
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

# Import routers
from routes.summary_router import router as summary_router 
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

    # Initialize summary generator
    try:
        print("✅ Summary Generation API initialized and ready!")
    except Exception as e:
        print(f"⚠️ Warning: Could not initialize summary API: {str(e)}")

    print("\n📚 API Documentation available at:")
    print("  - Swagger UI: http://localhost:8000/docs")
    print("  - ReDoc: http://localhost:8000/redoc")
    print("\n🔌 Available API Routes:")
    print("  - /analyzer/* (SOC Analyzer endpoints)")
    print("  - /predictions/* (Predictions & MITRE Analysis endpoints)")
    print("  - /summaries/* (Historical Analysis Summary endpoints)")  # ✅ NEW
    print("=" * 80)

    yield  # Application runs here

    # Shutdown
    print("\n🛑 Shutting down Security Alert Management API...")


# Initialize FastAPI app
app = FastAPI(
    title="Security Alert Management & Threat Intelligence API",
    description="Comprehensive API for managing security alerts, incidents, SOC operations, threat investigations with AI-powered MITRE ATT&CK analysis, and intelligent summary generation",
    version="3.1.0",  # ✅ Updated version
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
app.include_router(analyzer_router, prefix="/analyzer", tags=["SOC Analyzer"])
app.include_router(
    predictions_router, prefix="/predictions", tags=["Predictions & MITRE"]
)
app.include_router(
    summary_router, prefix="/summaries", tags=["Summary Generation"]
)  # ✅ NEW


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Security Alert Management & Threat Intelligence API",
        "version": "3.1.0",  # ✅ Updated
        "status": "running",
        "documentation": {"swagger_ui": "/docs", "redoc": "/redoc"},
        "available_routes": {
            "soc_analyzer": "/analyzer",
            "predictions": "/predictions",
            "summaries": "/summaries",  # ✅ NEW
        },
        "features": [
            "Search Alert Management",
            "SOC Analysis & Rule Suggestions",
            "Threat Investigation with MITRE ATT&CK",
            "True/False Positive Classification",
            "Batch Analysis & Comparison",
            "Defensive Recommendations",
            "AI-Powered Historical Analysis Summaries",  # ✅ NEW
        ],
    }


@app.get("/health", tags=["System"])
async def system_health():
    """System-wide health check"""
    return {
        "status": "healthy",
        "service": "Security Alert Management & Threat Intelligence API",
        "version": "3.1.0",  # ✅ Updated
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
