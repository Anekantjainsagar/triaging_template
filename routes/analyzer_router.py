import pandas as pd
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from fastapi import APIRouter, HTTPException

# Import your backend analyzer
from backend.alert_analysis.backend import SecurityAlertAnalyzerCrew
from backend.alert_analysis.soc_analyzer import IntelligentSOCAnalyzer

# Create router
router = APIRouter()

# Global cache for analyzers
_soc_analyzer: Optional[IntelligentSOCAnalyzer] = None
_alert_analyzer: Optional[SecurityAlertAnalyzerCrew] = None
_cache_timestamp = None


# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================


class RuleSuggestionRequest(BaseModel):
    """Request model for rule suggestions"""

    query: str = Field(
        ..., description="Search query for rule suggestions", min_length=1
    )
    top_k: int = Field(5, ge=1, le=20, description="Number of suggestions to return")


class RuleSuggestion(BaseModel):
    """Individual rule suggestion"""

    rule: str
    score: float
    incident_count: int
    match_type: str = "text_similarity"


class RuleSuggestionsResponse(BaseModel):
    """Response model for rule suggestions"""

    success: bool
    query: str
    total_found: int
    suggestions: List[RuleSuggestion]
    timestamp: str


class AnalyzeAlertRequest(BaseModel):
    """Request model for alert analysis"""

    alert_name: str = Field(..., description="Alert/Rule name to analyze", min_length=1)


class AnalyzeAlertResponse(BaseModel):
    """Response model for alert analysis"""

    success: bool
    alert_name: str
    analysis: str
    timestamp: str


class HistoricalDataRequest(BaseModel):
    """Request model for historical data"""

    rule_name: str = Field(..., description="Rule name to get historical data")


class HistoricalDataResponse(BaseModel):
    """Response model for historical data"""

    success: bool
    rule_name: str
    total_incidents: int
    data: List[Dict[str, Any]]
    timestamp: str


class SystemStatsResponse(BaseModel):
    """Response model for system statistics"""

    success: bool
    total_records: int
    unique_rules: int
    data_sources: int
    timestamp: str


class AnalyzerStatusResponse(BaseModel):
    """Response model for analyzer-specific status check"""

    status: str
    timestamp: str
    soc_analyzer_loaded: bool
    alert_analyzer_loaded: bool
    cache_timestamp: Optional[str] = None
    total_records: int = 0


class LoadDataResponse(BaseModel):
    """Response model for load data endpoint"""

    success: bool
    total_records: int
    unique_rules: int
    message: str
    timestamp: str


class ErrorResponse(BaseModel):
    """Standard error response"""

    success: bool = False
    error: str
    detail: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================


def get_analyzers(force_reload: bool = False):
    """
    Load and cache analyzer instances

    Args:
        force_reload: Force reload analyzers

    Returns:
        Tuple of (soc_analyzer, alert_analyzer)

    Raises:
        HTTPException: If analyzer initialization fails
    """
    global _soc_analyzer, _alert_analyzer, _cache_timestamp

    if force_reload or _soc_analyzer is None or _alert_analyzer is None:
        try:
            # Initialize SOC Analyzer
            soc_analyzer = IntelligentSOCAnalyzer(
                data_directory="data", ollama_model="qwen2.5:3b"
            )

            if not soc_analyzer.load_and_process_data():
                raise Exception("Failed to load SOC data")

            # Initialize Alert Analyzer
            alert_analyzer = SecurityAlertAnalyzerCrew()

            _soc_analyzer = soc_analyzer
            _alert_analyzer = alert_analyzer
            _cache_timestamp = datetime.now()

            print(f"✅ Loaded analyzers with {len(_soc_analyzer.df)} records")
            return _soc_analyzer, _alert_analyzer

        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Error initializing analyzers: {str(e)}"
            )

    return _soc_analyzer, _alert_analyzer


# ============================================================================
# API Endpoints
# ============================================================================


@router.get(
    "/status",  # CHANGED from /health to /status to avoid conflict
    response_model=AnalyzerStatusResponse,
    summary="Analyzer status check",
    description="Check if the SOC analyzer service is healthy and analyzers are loaded",
)
async def analyzer_status():
    """
    Status check endpoint for SOC analyzer service

    Returns status, analyzer loading state, and cache information
    """
    return AnalyzerStatusResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        soc_analyzer_loaded=_soc_analyzer is not None,
        alert_analyzer_loaded=_alert_analyzer is not None,
        cache_timestamp=_cache_timestamp.isoformat() if _cache_timestamp else None,
        total_records=(
            len(_soc_analyzer.df)
            if _soc_analyzer and _soc_analyzer.df is not None
            else 0
        ),
    )


@router.post(
    "/load-data",
    response_model=LoadDataResponse,
    summary="Load SOC data",
    description="Load or reload SOC analyzer data from the data directory",
)
async def load_data():
    """
    Load or reload SOC analyzer data from files

    This endpoint forces a reload of all data and reinitializes analyzers.
    Use this when new data files are added or existing files are updated.

    Returns:
        LoadDataResponse with success status and statistics
    """
    try:
        soc_analyzer, _ = get_analyzers(force_reload=True)

        total_records = len(soc_analyzer.df) if soc_analyzer.df is not None else 0
        unique_rules = (
            soc_analyzer.df["RULE"].nunique()
            if "RULE" in soc_analyzer.df.columns
            else 0
        )

        return LoadDataResponse(
            success=True,
            total_records=total_records,
            unique_rules=unique_rules,
            message=f"Successfully loaded {total_records} records with {unique_rules} unique rules",
            timestamp=datetime.now().isoformat(),
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Unexpected error loading data: {str(e)}"
        )


@router.post(
    "/suggestions",
    response_model=RuleSuggestionsResponse,
    summary="Get rule suggestions",
    description="Search for rule suggestions based on query with intelligent matching",
)
async def get_rule_suggestions(request: RuleSuggestionRequest):
    """
    Get rule suggestions based on search query

    This endpoint searches across rule names and returns ranked suggestions
    using intelligent text similarity and rule number matching.

    Args:
        request: RuleSuggestionRequest with query and top_k parameters

    Returns:
        RuleSuggestionsResponse with matching rule suggestions
    """
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query parameter cannot be empty")

    # Get cached analyzer
    soc_analyzer, _ = get_analyzers()

    if soc_analyzer.df is None or soc_analyzer.df.empty:
        raise HTTPException(
            status_code=500,
            detail="No SOC data available. Please load data first using /load-data endpoint.",
        )

    # Get suggestions
    try:
        suggestions = soc_analyzer.get_rule_suggestions(
            request.query, top_k=request.top_k
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error getting suggestions: {str(e)}"
        )

    # Convert to Pydantic models
    suggestion_models = [
        RuleSuggestion(
            rule=s["rule"],
            score=s["score"],
            incident_count=s["incident_count"],
            match_type=s.get("match_type", "text_similarity"),
        )
        for s in suggestions
    ]

    return RuleSuggestionsResponse(
        success=True,
        query=request.query,
        total_found=len(suggestion_models),
        suggestions=suggestion_models,
        timestamp=datetime.now().isoformat(),
    )


@router.post(
    "/analyze",
    response_model=AnalyzeAlertResponse,
    summary="Analyze alert with AI",
    description="Generate comprehensive AI-powered threat intelligence analysis for an alert",
)
async def analyze_alert(request: AnalyzeAlertRequest):
    """
    Analyze alert with AI-powered threat intelligence

    This endpoint generates comprehensive analysis including:
    - Technical threat breakdown
    - MITRE ATT&CK technique mapping
    - Threat actor intelligence
    - Business impact assessment

    Args:
        request: AnalyzeAlertRequest with alert_name

    Returns:
        AnalyzeAlertResponse with generated analysis
    """
    if not request.alert_name.strip():
        raise HTTPException(status_code=400, detail="Alert name cannot be empty")

    # Get cached analyzer
    _, alert_analyzer = get_analyzers()

    try:
        # Generate analysis (this may take time due to LLM processing)
        analysis = alert_analyzer.analyze_alert(request.alert_name)

        return AnalyzeAlertResponse(
            success=True,
            alert_name=request.alert_name,
            analysis=analysis,
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing alert: {str(e)}")


"""
Replace the get_historical_data endpoint in analyzer_router.py
This preserves original column names and data types
"""


@router.post(
    "/historical-data",
    response_model=HistoricalDataResponse,
    summary="Get historical incident data",
    description="Retrieve historical incident data for a specific rule",
)
async def get_historical_data(request: HistoricalDataRequest):
    """
    Get historical incident data for a rule

    This endpoint retrieves all historical incidents associated with
    a specific rule name from the SOC tracker data.

    Args:
        request: HistoricalDataRequest with rule_name

    Returns:
        HistoricalDataResponse with historical incident data
    """
    if not request.rule_name.strip():
        raise HTTPException(status_code=400, detail="Rule name cannot be empty")

    # Get cached analyzer
    soc_analyzer, _ = get_analyzers()

    try:
        # Filter data for specific rule
        matching_data = soc_analyzer.df[
            soc_analyzer.df["RULE"] == request.rule_name
        ].copy()

        if matching_data.empty:
            raise HTTPException(
                status_code=404,
                detail=f"No historical data found for rule: {request.rule_name}",
            )

        # Convert to dict records with proper serialization
        # KEEP ORIGINAL COLUMN NAMES
        records = []
        for _, row in matching_data.iterrows():
            record = {}
            for key, value in row.items():
                if pd.isna(value):
                    record[key] = None
                elif isinstance(value, (pd.Timestamp, datetime)):
                    record[key] = value.isoformat()
                elif isinstance(value, (int, float)):
                    # Keep numeric types as numbers, not strings
                    record[key] = value
                else:
                    record[key] = str(value)
            records.append(record)

        return HistoricalDataResponse(
            success=True,
            rule_name=request.rule_name,
            total_incidents=len(records),
            data=records,
            timestamp=datetime.now().isoformat(),
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving historical data: {str(e)}"
        )


@router.get(
    "/stats",
    response_model=SystemStatsResponse,
    summary="Get system statistics",
    description="Get overall system statistics including record counts and unique rules",
)
async def get_system_stats():
    """
    Get system statistics

    Returns overall statistics about the SOC data including
    total records, unique rules, and data sources.

    Returns:
        SystemStatsResponse with system statistics
    """
    # Get cached analyzer
    soc_analyzer, _ = get_analyzers()

    if soc_analyzer.df is None or soc_analyzer.df.empty:
        raise HTTPException(
            status_code=500, detail="No SOC data available. Please load data first."
        )

    try:
        total_records = len(soc_analyzer.df)
        unique_rules = (
            soc_analyzer.df["RULE"].nunique()
            if "RULE" in soc_analyzer.df.columns
            else 0
        )
        data_sources = (
            soc_analyzer.df["source_file"].nunique()
            if "source_file" in soc_analyzer.df.columns
            else 0
        )

        return SystemStatsResponse(
            success=True,
            total_records=total_records,
            unique_rules=unique_rules,
            data_sources=data_sources,
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error getting system stats: {str(e)}"
        )
