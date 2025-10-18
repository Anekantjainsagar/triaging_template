from typing import Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

from backend.historical_analysis_backend import (
    generate_data_summary_with_llm,
    extract_summary_data,
)
import pandas as pd
from frontend.utils.alert_analysis.metrices import extract_detailed_metrics

# Create router
router = APIRouter()

# Global cache for summaries
_summary_cache: Dict[str, Dict[str, Any]] = {}


# ============================================================================
# Helper Functions
# ============================================================================


def convert_timestamps_to_serializable(data_df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert all datetime/timestamp columns to strings for JSON serialization

    Args:
        data_df: Input DataFrame with potential timestamp columns

    Returns:
        DataFrame with timestamps converted to strings
    """
    df_copy = data_df.copy()

    # Find all datetime columns
    datetime_columns = df_copy.select_dtypes(
        include=["datetime64", "datetime64[ns]", "datetimetz"]
    ).columns

    # Convert to ISO format strings
    for col in datetime_columns:
        df_copy[col] = df_copy[col].astype(str)

    # Also handle any remaining Timestamp objects in object columns
    for col in df_copy.select_dtypes(include=["object"]).columns:
        df_copy[col] = df_copy[col].apply(
            lambda x: (
                str(x)
                if pd.api.types.is_datetime64_any_dtype(type(x))
                or isinstance(x, pd.Timestamp)
                else x
            )
        )

    return df_copy


def make_json_serializable(obj):
    """
    Recursively convert numpy/pandas types to native Python types for JSON serialization

    Args:
        obj: Any object (dict, list, numpy type, etc.)

    Returns:
        JSON-serializable version of the object
    """
    import numpy as np

    if isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(make_json_serializable(item) for item in obj)
    elif isinstance(obj, (np.integer, np.int64, np.int32, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32, np.float16)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (pd.Timestamp, pd.Timedelta)):
        return str(obj)
    elif pd.isna(obj):
        return None
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    else:
        return obj


# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================


class GenerateSummaryRequest(BaseModel):
    """Request model for generating a summary"""

    section_name: str = Field(
        ...,
        description="Name of the section to generate summary for",
        examples=[
            "Alert Classification",
            "VIP User Distribution",
            "Response Time Analysis",
        ],
    )
    data: Dict[str, Any] = Field(
        ..., description="Data dictionary containing metrics for the section"
    )


class GenerateSummaryResponse(BaseModel):
    """Response model for summary generation"""

    success: bool
    section_name: str
    summary: str
    timestamp: str
    cached: bool = False


class GenerateMultipleSummariesRequest(BaseModel):
    """Request model for generating multiple summaries"""

    historical_data: list = Field(
        ..., description="List of historical incident records (dict format)"
    )


class GenerateMultipleSummariesResponse(BaseModel):
    """Response model for multiple summaries"""

    success: bool
    summaries: Dict[str, str]
    metrics: Dict[str, Any]
    summary_data: Dict[str, Any]
    total_incidents: int
    timestamp: str
    cached: bool = False


class SummaryCacheInfo(BaseModel):
    """Response model for cache information"""

    success: bool
    total_cached_summaries: int
    cache_keys: list
    timestamp: str


class ClearCacheResponse(BaseModel):
    """Response model for cache clearing"""

    success: bool
    message: str
    cleared_count: int
    timestamp: str


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/", tags=["Root"])
async def summary_root():
    """Root endpoint for summary API"""
    return {
        "name": "Historical Analysis Summary Generation API",
        "version": "1.0.0",
        "status": "running",
        "available_routes": {
            "generate_single": "/generate/single",
            "generate_multiple": "/generate/multiple",
            "cache_info": "/cache/info",
            "clear_cache": "/cache/clear",
        },
        "supported_sections": [
            "Alert Classification",
            "VIP User Distribution",
            "Response Time Analysis",
            "Daily Incident Timeline",
            "Incident Pattern Heatmap",
            "Resolution Time Distribution",
        ],
    }


@router.post(
    "/generate/single",
    response_model=GenerateSummaryResponse,
    summary="Generate single summary",
    description="Generate LLM-powered summary for a specific section with provided data",
)
async def generate_single_summary(request: GenerateSummaryRequest):
    """
    Generate AI summary for a single section

    This endpoint generates a professional 2-3 line summary using either
    Google Gemini or Ollama LLM based on the provided metrics.

    Args:
        request: GenerateSummaryRequest with section_name and data

    Returns:
        GenerateSummaryResponse with generated summary
    """
    if not request.section_name.strip():
        raise HTTPException(status_code=400, detail="Section name cannot be empty")

    if not request.data:
        raise HTTPException(status_code=400, detail="Data cannot be empty")

    # Create cache key
    import hashlib
    import json

    cache_key = hashlib.md5(
        (request.section_name + json.dumps(request.data, sort_keys=True)).encode()
    ).hexdigest()

    # Check cache
    if cache_key in _summary_cache:
        cached_result = _summary_cache[cache_key]
        return GenerateSummaryResponse(
            success=True,
            section_name=request.section_name,
            summary=cached_result["summary"],
            timestamp=cached_result["timestamp"],
            cached=True,
        )

    try:
        # Generate summary using backend function
        summary = generate_data_summary_with_llm(request.section_name, request.data)

        # Cache result
        _summary_cache[cache_key] = {
            "summary": summary,
            "timestamp": datetime.now().isoformat(),
        }

        return GenerateSummaryResponse(
            success=True,
            section_name=request.section_name,
            summary=summary,
            timestamp=datetime.now().isoformat(),
            cached=False,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error generating summary: {str(e)}"
        )


@router.post(
    "/generate/multiple",
    response_model=GenerateMultipleSummariesResponse,
    summary="Generate multiple summaries",
    description="Generate summaries for all sections from historical incident data",
)
async def generate_multiple_summaries(request: GenerateMultipleSummariesRequest):
    """
    Generate AI summaries for all relevant sections

    This endpoint takes raw historical incident data, extracts metrics,
    and generates summaries for all applicable sections:
    - Alert Classification
    - VIP User Distribution
    - Response Time Analysis

    Args:
        request: GenerateMultipleSummariesRequest with historical_data

    Returns:
        GenerateMultipleSummariesResponse with all summaries and metrics
    """
    if not request.historical_data:
        raise HTTPException(status_code=400, detail="Historical data cannot be empty")

    try:
        # 🔧 FIX: Convert to DataFrame and handle timestamps
        data_df = pd.DataFrame(request.historical_data)

        if data_df.empty:
            raise HTTPException(status_code=400, detail="Historical data is empty")

        # 🔧 FIX: Convert timestamps before any JSON operations
        data_df_clean = convert_timestamps_to_serializable(data_df)

        # Create cache key using cleaned data
        import hashlib
        import json

        data_hash = hashlib.md5(
            json.dumps(
                data_df_clean.head().to_dict(), sort_keys=True, default=str
            ).encode()
        ).hexdigest()
        cache_key = f"multiple_{data_hash}"

        # Check cache
        if cache_key in _summary_cache:
            cached_result = _summary_cache[cache_key]
            return GenerateMultipleSummariesResponse(
                success=True,
                summaries=cached_result["summaries"],
                metrics=make_json_serializable(cached_result["metrics"]),  # ✅ ADD THIS
                summary_data=make_json_serializable(
                    cached_result["summary_data"]
                ),  # ✅ ADD THIS
                total_incidents=cached_result["total_incidents"],
                timestamp=cached_result["timestamp"],
                cached=True,
            )

        # Extract metrics (use original data_df for metric calculations)
        metrics = extract_detailed_metrics(data_df)
        summary_data = extract_summary_data(metrics, data_df)

        # Generate summaries for each section
        summaries = {}

        # Alert Classification
        if "classification_analysis" in metrics:
            summaries["Alert Classification"] = generate_data_summary_with_llm(
                "Alert Classification", summary_data.get("Alert Classification", {})
            )

        # VIP User Distribution
        if "vip_analysis" in metrics:
            summaries["VIP User Distribution"] = generate_data_summary_with_llm(
                "VIP User Distribution",
                summary_data.get("VIP User Distribution", {}),
            )

        # Response Time Analysis
        if "mttr_analysis" in metrics or "mttd_analysis" in metrics:
            summaries["Response Time Analysis"] = generate_data_summary_with_llm(
                "Response Time Analysis",
                summary_data.get("Response Time Analysis", {}),
            )

        # Daily Incident Timeline
        if "date_range" in metrics and "daily_patterns" in metrics:
            summaries["Daily Incident Timeline"] = generate_data_summary_with_llm(
                "Daily Incident Timeline",
                summary_data.get("Daily Incident Timeline", {}),
            )

        # Incident Pattern Heatmap
        if "weekly_patterns" in metrics:
            summaries["Incident Pattern Heatmap"] = generate_data_summary_with_llm(
                "Incident Pattern Heatmap",
                summary_data.get("Incident Pattern Heatmap", {}),
            )

        # Resolution Time Distribution
        if "mttr_analysis" in metrics:
            summaries["Resolution Time Distribution"] = generate_data_summary_with_llm(
                "Resolution Time Distribution",
                summary_data.get("Resolution Time Distribution", {}),
            )

        # ✅ ADD THESE TWO LINES HERE (before caching)
        metrics = make_json_serializable(metrics)
        summary_data = make_json_serializable(summary_data)

        # Cache result
        _summary_cache[cache_key] = {
            "summaries": summaries,
            "metrics": metrics,  # Now safe to cache
            "summary_data": summary_data,  # Now safe to cache
            "total_incidents": len(data_df),
            "timestamp": datetime.now().isoformat(),
        }

        return GenerateMultipleSummariesResponse(
            success=True,
            summaries=summaries,
            metrics=metrics,  # Already serialized above
            summary_data=summary_data,  # Already serialized above
            total_incidents=len(data_df),
            timestamp=datetime.now().isoformat(),
            cached=False,
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        # 🔧 FIX: Better error logging
        import traceback

        error_details = traceback.format_exc()
        print(f"❌ Error in generate_multiple_summaries: {error_details}")
        raise HTTPException(
            status_code=500, detail=f"Error generating summaries: {str(e)}"
        )


@router.get(
    "/cache/info",
    response_model=SummaryCacheInfo,
    summary="Get cache information",
    description="Get information about cached summaries",
)
async def get_cache_info():
    """
    Get information about summary cache

    Returns:
        SummaryCacheInfo with cache statistics
    """
    return SummaryCacheInfo(
        success=True,
        total_cached_summaries=len(_summary_cache),
        cache_keys=list(_summary_cache.keys())[:10],  # First 10 keys only
        timestamp=datetime.now().isoformat(),
    )


@router.delete(
    "/cache/clear",
    response_model=ClearCacheResponse,
    summary="Clear summary cache",
    description="Clear all cached summaries",
)
async def clear_summary_cache():
    """
    Clear all cached summaries

    Returns:
        ClearCacheResponse with clearing status
    """
    global _summary_cache
    cleared_count = len(_summary_cache)
    _summary_cache = {}

    return ClearCacheResponse(
        success=True,
        message=f"Successfully cleared {cleared_count} cached summaries",
        cleared_count=cleared_count,
        timestamp=datetime.now().isoformat(),
    )
