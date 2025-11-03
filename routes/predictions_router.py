import io
import pandas as pd
import numpy as np  # ✅ ADD THIS IMPORT
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from fastapi import APIRouter, HTTPException, Query, File, UploadFile
from backend.backed_fixes import extract_investigation_steps_fixed, clean_dataframe # Import fixed extraction

# Import backend analyzer
from backend.predictions_backend import InvestigationAnalyzer

# Create router
router = APIRouter()

import logging
from backend.backed_fixes import extract_investigation_steps_fixed, clean_dataframe

logger = logging.getLogger(__name__)

# Global cache for analyzers and data
_investigation_analyzer: Optional[InvestigationAnalyzer] = None
_uploaded_data: Optional[pd.DataFrame] = None
_analysis_cache: Dict[str, Dict[str, Any]] = {}
_comparison_cache: Dict[str, Dict[str, Any]] = {}
_api_statistics = {
    "total_analyses": 0,
    "total_batch_analyses": 0,
    "total_comparisons": 0,
    "last_analysis_time": None,
    "analyses_by_classification": {
        "TRUE POSITIVE": 0,
        "FALSE POSITIVE": 0,
        "BENIGN POSITIVE": 0,
    },
}


# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================


class ExcelUploadResponse(BaseModel):
    """Response for Excel file upload"""

    success: bool
    message: str
    total_rows: int
    columns: List[str]
    preview_data: Optional[List[Dict[str, Any]]] = None
    timestamp: str


class AnalyzeInvestigationRequest(BaseModel):
    """Request model for investigation analysis"""

    username: str = Field(..., description="Username to analyze", min_length=1)


class InitialAnalysisResponse(BaseModel):
    """Response model for initial analysis"""

    success: bool
    username: str
    classification: str
    risk_level: str
    confidence_score: int
    summary: str
    timestamp: str


class MITREAnalysisResponse(BaseModel):
    """Response model for MITRE analysis"""

    success: bool
    username: str
    mitre_analysis: Dict[str, Any]
    timestamp: str


class CompleteAnalysisResponse(BaseModel):
    """Response model for complete analysis"""

    success: bool
    username: str
    analysis_timestamp: str
    initial_analysis: Dict[str, Any]
    mitre_attack_analysis: Optional[Dict[str, Any]]
    executive_summary: Optional[Dict[str, Any]]
    geographic_risk: Optional[Dict[str, Any]]
    status: str


class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis"""

    usernames: List[str] = Field(..., description="List of usernames to analyze")


class BatchAnalysisResponse(BaseModel):
    """Response for batch analysis"""

    success: bool
    total_usernames: int
    completed: int
    failed: int
    results: List[Dict[str, Any]]
    timestamp: str


class ComparisonRequest(BaseModel):
    """Request model for comparing analyses"""

    username1: str = Field(..., description="First username")
    username2: str = Field(..., description="Second username")


class ComparisonResponse(BaseModel):
    """Response for analysis comparison"""

    success: bool
    comparison: Dict[str, Any]
    similarities: List[str]
    differences: List[str]
    timestamp: str


class PredictionsStatusResponse(BaseModel):
    """Response for predictions analyzer status"""

    status: str
    timestamp: str
    analyzer_loaded: bool
    data_loaded: bool
    total_analyses: int
    cached_analyses: int


# ============================================================================
# Helper Functions
# ============================================================================


@router.get("/", tags=["Root"])
async def predictions_root():
    """Root endpoint for predictions API"""
    return {
        "name": "Predictions & MITRE Analysis API",
        "version": "1.0.0",
        "status": "running",
        "available_routes": {
            "upload_excel": "/upload/excel",
            "analyze_initial": "/analyze/initial",
            "analyze_mitre": "/analyze/mitre",
            "analyze_complete": "/analyze/complete",
            "batch_analysis": "/batch/analyze",
            "compare": "/compare/analyses",
            "cache": "/cache/info",
            "statistics": "/statistics",
            "status": "/status",
        },
    }


# predictions_router.py

def get_analyzer(api_key: str) -> InvestigationAnalyzer:
    """Get or initialize the investigation analyzer"""
    global _investigation_analyzer

    if _investigation_analyzer is None:
        try:
            if not api_key:
                # This would raise a 400 error, not a 500, but is good to check
                raise HTTPException(
                    status_code=400, detail="API key is required for analysis"
                )

            # 🚨 CRITICAL POINT 🚨
            # This line attempts to initialize the model. If it fails due to an
            # invalid key or network issue, it raises an exception which is caught
            # and results in a 500 error, leaving _investigation_analyzer as None.
            _investigation_analyzer = InvestigationAnalyzer(api_key) 
            print("✅ Investigation Analyzer initialized with API key")
        except Exception as e:
            # 💡 This is the path leading to analyzer_loaded: false
            # and the 500 error in analysis endpoints.
            raise HTTPException(
                status_code=500, detail=f"Failed to initialize analyzer: {str(e)}"
            )

    return _investigation_analyzer
# ============================================================================
# Status Endpoints
# ============================================================================


@router.get(
    "/status",
    response_model=PredictionsStatusResponse,
    summary="Predictions API status",
    description="Check if the Predictions analyzer service is healthy",
)
async def predictions_status():
    """Status check endpoint for Predictions service"""
    return PredictionsStatusResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        analyzer_loaded=_investigation_analyzer is not None,
        data_loaded=_uploaded_data is not None,
        total_analyses=_api_statistics["total_analyses"],
        cached_analyses=len(_analysis_cache),
    )


@router.get("/statistics", tags=["Status"])
async def get_statistics():
    """Get API usage statistics"""
    return {
        "success": True,
        "total_analyses": _api_statistics["total_analyses"],
        "total_batch_analyses": _api_statistics["total_batch_analyses"],
        "total_comparisons": _api_statistics["total_comparisons"],
        "last_analysis_time": _api_statistics["last_analysis_time"],
        "classifications": _api_statistics["analyses_by_classification"],
        "data_loaded": _uploaded_data is not None,
        "cached_analyses": len(_analysis_cache),
        "cached_comparisons": len(_comparison_cache),
        "timestamp": datetime.now().isoformat(),
    }


# ============================================================================
# Upload Endpoints
# ============================================================================


# Update the upload endpoint to use cleaned data
@router.post(
    "/upload/excel",
    response_model=ExcelUploadResponse,
    summary="Upload investigation Excel file",
    description="Upload Excel file with investigation data",
)
async def upload_excel(file: UploadFile = File(...)):
    """Upload investigation data in Excel format with enhanced NaN handling"""
    global _uploaded_data

    try:
        # Read file contents
        contents = await file.read()

        # Parse Excel
        df = pd.read_excel(io.BytesIO(contents))

        # Use the fixed cleaning function
        df_clean = clean_dataframe(df)

        # Store globally
        _uploaded_data = df_clean

        # Create preview with cleaned data
        preview_df = df_clean.head(3).copy()
        preview_data = preview_df.to_dict(orient="records")

        # Final cleanup pass
        for record in preview_data:
            for key in list(record.keys()):
                value = record[key]
                if value is None or (
                    isinstance(value, float) and (np.isnan(value) or np.isinf(value))
                ):
                    record[key] = None

        return ExcelUploadResponse(
            success=True,
            message=f"Successfully uploaded {file.filename}",
            total_rows=len(df_clean),
            columns=df_clean.columns.tolist(),
            preview_data=preview_data,
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Failed to parse Excel file: {str(e)}"
        )


@router.get("/upload/preview", tags=["Upload"])
async def get_upload_preview():
    """Get preview of uploaded data with FIXED NaN handling"""
    if _uploaded_data is None:
        raise HTTPException(
            status_code=400,
            detail="No data uploaded yet. Please upload an Excel file first.",
        )

    try:
        # Create a clean copy of the data for preview
        preview_df = _uploaded_data.head(10).copy()

        # ✅ COMPREHENSIVE NaN CLEANING
        # Replace all problematic values
        preview_df = preview_df.replace(
            {
                pd.NA: None,
                pd.NaT: None,
                float("nan"): None,
                float("inf"): None,
                float("-inf"): None,
            }
        )

        # Use where to replace remaining NaN values
        preview_df = preview_df.where(pd.notna(preview_df), None)

        # Convert to dictionary
        preview_data = preview_df.to_dict(orient="records")

        # ✅ FINAL CLEANUP PASS - Handle any remaining problematic values
        for record in preview_data:
            for key in list(record.keys()):
                value = record[key]

                # Check for any type of NaN/None/NA
                if value is None or value is pd.NA or value is pd.NaT:
                    record[key] = None
                    continue

                # Check for float NaN/inf
                if isinstance(value, float):
                    if np.isnan(value) or np.isinf(value):
                        record[key] = None
                        continue

                # Check for string representations of NaN
                if isinstance(value, str) and value.lower() in [
                    "nan",
                    "nat",
                    "none",
                    "<na>",
                ]:
                    record[key] = None

        return {
            "success": True,
            "total_rows": len(_uploaded_data),
            "columns": _uploaded_data.columns.tolist(),
            "preview_data": preview_data,
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as e:
        # Enhanced error reporting
        import traceback

        error_details = traceback.format_exc()
        print(f"❌ Preview error: {str(e)}")
        print(f"📋 Traceback: {error_details}")

        raise HTTPException(
            status_code=500,
            detail=f"Error generating preview: {str(e)}\n\nDetails: {error_details}",
        )


# ============================================================================
# Analysis Endpoints
# ============================================================================


@router.post("/analyze/initial", response_model=InitialAnalysisResponse)
async def analyze_initial(request: AnalyzeInvestigationRequest, api_key: str = ""):
    """Perform initial classification analysis - FIXED VERSION"""

    logger.info(f"=" * 60)
    logger.info(f"ANALYZE INITIAL REQUEST: {request.username}")

    if _uploaded_data is None or _uploaded_data.empty:
        logger.error("No data uploaded")
        raise HTTPException(
            status_code=400, detail="No data uploaded. Upload Excel first."
        )

    logger.info(f"Uploaded data shape: {_uploaded_data.shape}")
    logger.info(f"Uploaded data columns: {_uploaded_data.columns.tolist()}")

    if not request.username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    try:
        analyzer = get_analyzer(api_key)

        # ✅ Use fixed extraction
        investigation_steps = extract_investigation_steps_fixed(
            _uploaded_data, request.username
        )

        logger.info(f"Extracted {len(investigation_steps)} steps")

        if not investigation_steps:
            logger.error(f"No investigation data found for: {request.username}")
            raise HTTPException(
                status_code=404,
                detail=f"No investigation data found for user: {request.username}",
            )

        # ✅ Log first step for verification
        if investigation_steps:
            first_step = investigation_steps[0]
            logger.info(f"First step: {first_step['step_name']}")
            logger.info(f"First step output length: {len(first_step['output'])}")

        initial_analysis = analyzer.perform_initial_analysis(
            request.username, investigation_steps
        )

        if not initial_analysis:
            logger.error("Initial analysis returned None")
            raise HTTPException(status_code=500, detail="Initial analysis failed")

        logger.info(f"Analysis complete: {initial_analysis.get('classification')}")

        # Update statistics
        _api_statistics["total_analyses"] += 1
        _api_statistics["last_analysis_time"] = datetime.now().isoformat()
        classification = initial_analysis.get("classification", "UNKNOWN")
        if classification in _api_statistics["analyses_by_classification"]:
            _api_statistics["analyses_by_classification"][classification] += 1

        return InitialAnalysisResponse(
            success=True,
            username=request.username,
            classification=initial_analysis.get("classification", "UNKNOWN"),
            risk_level=initial_analysis.get("risk_level", "UNKNOWN"),
            confidence_score=initial_analysis.get("confidence_score", 0),
            summary=str(
                initial_analysis.get("key_findings", [{}])[0].get(
                    "details", "Analysis complete"
                )
            ),
            timestamp=datetime.now().isoformat(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error in initial analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


@router.post(
    "/analyze/mitre",
    response_model=MITREAnalysisResponse,
    summary="MITRE ATT&CK analysis",
    description="Generate MITRE ATT&CK framework mapping with sub-techniques",
)
async def analyze_mitre(request: AnalyzeInvestigationRequest, api_key: str = ""):
    """Perform MITRE ATT&CK analysis"""
    if _uploaded_data is None or _uploaded_data.empty:
        raise HTTPException(
            status_code=400,
            detail="No data uploaded. Please upload an Excel file first.",
        )

    if not request.username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    try:
        analyzer = get_analyzer(api_key)
        # ✅ Corrected: Use the fixed extraction function
        investigation_steps = extract_investigation_steps_fixed(
            _uploaded_data, request.username
        )

        if not investigation_steps:
            raise HTTPException(
                status_code=404,
                detail=f"No investigation data found for user: {request.username}",
            )

        initial_analysis = analyzer.perform_initial_analysis(
            request.username, investigation_steps
        )

        if not initial_analysis:
            raise HTTPException(
                status_code=500, detail="Could not perform initial analysis"
            )

        mitre_analysis = analyzer.mitre_analyzer.analyze_mitre_attack_chain(
            request.username,
            initial_analysis.get("classification", "UNKNOWN"),
            initial_analysis,
            investigation_steps,
        )

        if not mitre_analysis:
            raise HTTPException(status_code=500, detail="MITRE ATT&CK analysis failed")

        return MITREAnalysisResponse(
            success=True,
            username=request.username,
            mitre_analysis=mitre_analysis.get("mitre_attack_analysis", {}),
            timestamp=datetime.now().isoformat(),
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error in MITRE analysis: {str(e)}"
        )


@router.post(
    "/analyze/complete",
    response_model=CompleteAnalysisResponse,
    summary="Complete investigation analysis",
    description="Generate comprehensive analysis with initial classification and MITRE mapping",
)
async def analyze_complete(request: AnalyzeInvestigationRequest, api_key: str = ""):
    """Perform complete investigation analysis"""
    if _uploaded_data is None or _uploaded_data.empty:
        raise HTTPException(
            status_code=400,
            detail="No data uploaded. Please upload an Excel file first.",
        )

    if not request.username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    cache_key = f"{request.username}_{hash(str(_uploaded_data.iloc[0, 0]))}"
    if cache_key in _analysis_cache:
        return CompleteAnalysisResponse(
            success=True, username=request.username, **_analysis_cache[cache_key]
        )

    try:
        analyzer = get_analyzer(api_key)
        # FIX: Call the correct, globally available fixed function
        investigation_steps = extract_investigation_steps_fixed(
            _uploaded_data, request.username
        )

        if not investigation_steps:
            raise HTTPException(
                status_code=404,
                detail=f"No investigation data found for user: {request.username}",
            )

        print(request.username, investigation_steps)
        complete_analysis = analyzer.perform_complete_analysis(
            request.username, investigation_steps
        )

        print(complete_analysis)
        if complete_analysis.get("status") != "success":
            raise HTTPException(status_code=500, detail="Analysis failed")

        _analysis_cache[cache_key] = {
            "analysis_timestamp": complete_analysis.get("analysis_timestamp"),
            "initial_analysis": complete_analysis.get("initial_analysis"),
            "mitre_attack_analysis": complete_analysis.get("mitre_attack_analysis"),
            "executive_summary": complete_analysis.get("executive_summary"),
            "geographic_risk": complete_analysis.get("geographic_risk"),
            "status": complete_analysis.get("status"),
        }

        _api_statistics["total_analyses"] += 1
        _api_statistics["last_analysis_time"] = datetime.now().isoformat()
        classification = complete_analysis.get("initial_analysis", {}).get(
            "classification", "UNKNOWN"
        )
        if classification in _api_statistics["analyses_by_classification"]:
            _api_statistics["analyses_by_classification"][classification] += 1

        return CompleteAnalysisResponse(
            success=True, username=request.username, **_analysis_cache[cache_key]
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        # Re-raise with detail to help debug 500 errors
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error in complete analysis: {str(e)}\n{error_details}")
        raise HTTPException(
            status_code=500, detail=f"Analysis error: {str(e)}"
        )


# ============================================================================
# Batch Analysis Endpoints
# ============================================================================


@router.post(
    "/batch/analyze",
    response_model=BatchAnalysisResponse,
    summary="Batch analysis",
    description="Analyze multiple users in a single request",
)
async def batch_analyze(request: BatchAnalysisRequest, api_key: str = ""):
    """Perform batch analysis on multiple usernames"""
    if _uploaded_data is None or _uploaded_data.empty:
        raise HTTPException(
            status_code=400,
            detail="No data uploaded. Please upload an Excel file first.",
        )

    if not request.usernames:
        raise HTTPException(status_code=400, detail="At least one username is required")

    try:
        analyzer = get_analyzer(api_key)
        results = []
        completed = 0
        failed = 0

        for username in request.usernames:
            try:
                # ✅ Corrected: Use the fixed extraction function
                investigation_steps = extract_investigation_steps_fixed(
                    _uploaded_data, username
                )

                if investigation_steps:
                    complete_analysis = analyzer.perform_complete_analysis(
                        username, investigation_steps
                    )

                    if complete_analysis.get("status") == "success":
                        results.append(
                            {
                                "username": username,
                                "success": True,
                                "classification": complete_analysis.get(
                                    "initial_analysis", {}
                                ).get("classification"),
                                "risk_level": complete_analysis.get(
                                    "initial_analysis", {}
                                ).get("risk_level"),
                                "confidence_score": complete_analysis.get(
                                    "initial_analysis", {}
                                ).get("confidence_score"),
                            }
                        )
                        completed += 1
                    else:
                        results.append(
                            {
                                "username": username,
                                "success": False,
                                "error": "Analysis returned non-success status",
                            }
                        )
                        failed += 1
                else:
                    results.append(
                        {
                            "username": username,
                            "success": False,
                            "error": "No investigation data found",
                        }
                    )
                    failed += 1

            except Exception as e:
                results.append(
                    {"username": username, "success": False, "error": str(e)}
                )
                failed += 1

        _api_statistics["total_batch_analyses"] += 1

        return BatchAnalysisResponse(
            success=True,
            total_usernames=len(request.usernames),
            completed=completed,
            failed=failed,
            results=results,
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error in batch analysis: {str(e)}"
        )


# ============================================================================
# Comparison Endpoints
# ============================================================================


@router.post(
    "/compare/analyses",
    response_model=ComparisonResponse,
    summary="Compare two analyses",
    description="Compare threat profiles between two users",
)
async def compare_analyses(request: ComparisonRequest, api_key: str = ""):
    """Compare two analyses"""
    if _uploaded_data is None or _uploaded_data.empty:
        raise HTTPException(status_code=400, detail="No data uploaded")

    cache_key = f"{request.username1}_{request.username2}"
    if cache_key in _comparison_cache:
        return ComparisonResponse(success=True, **_comparison_cache[cache_key])

    try:
        analyzer = get_analyzer(api_key)

        # Analyze both users
        analysis1 = analyzer.perform_complete_analysis(
            request.username1,
            # ✅ Corrected: Use the fixed extraction function
            extract_investigation_steps_fixed(_uploaded_data, request.username1),
        )

        analysis2 = analyzer.perform_complete_analysis(
            request.username2,
            # ✅ Corrected: Use the fixed extraction function
            extract_investigation_steps_fixed(_uploaded_data, request.username2),
        )

        if analysis1.get("status") != "success" or analysis2.get("status") != "success":
            raise HTTPException(
                status_code=500, detail="Failed to analyze one or both users"
            )

        # Compare classifications and risk levels
        similarities = []
        differences = []

        if analysis1.get("initial_analysis", {}).get("classification") == analysis2.get(
            "initial_analysis", {}
        ).get("classification"):
            similarities.append(
                f"Same classification: {analysis1.get('initial_analysis', {}).get('classification')}"
            )
        else:
            differences.append(
                f"Different classifications: {analysis1.get('initial_analysis', {}).get('classification')} vs {analysis2.get('initial_analysis', {}).get('classification')}"
            )

        # Compare techniques
        techniques1 = set(
            [
                t.get("technique")
                for t in analysis1.get("mitre_attack_analysis", {}).get(
                    "mitre_techniques_observed", []
                )
            ]
        )
        techniques2 = set(
            [
                t.get("technique")
                for t in analysis2.get("mitre_attack_analysis", {}).get(
                    "mitre_techniques_observed", []
                )
            ]
        )

        common_techniques = techniques1 & techniques2
        if common_techniques:
            similarities.append(
                f"Shared techniques: {', '.join(list(common_techniques)[:3])}"
            )

        unique_techniques1 = techniques1 - techniques2
        unique_techniques2 = techniques2 - techniques1
        if unique_techniques1 or unique_techniques2:
            differences.append(
                f"Unique techniques for user1: {len(unique_techniques1)}, User2: {len(unique_techniques2)}"
            )

        comparison = {
            "user1": request.username1,
            "user2": request.username2,
            "user1_classification": analysis1.get("initial_analysis", {}).get(
                "classification"
            ),
            "user2_classification": analysis2.get("initial_analysis", {}).get(
                "classification"
            ),
            "common_techniques": list(common_techniques),
            "unique_to_user1": list(unique_techniques1),
            "unique_to_user2": list(unique_techniques2),
        }

        _comparison_cache[cache_key] = {
            "comparison": comparison,
            "similarities": similarities,
            "differences": differences,
            "timestamp": datetime.now().isoformat(),
        }

        _api_statistics["total_comparisons"] += 1

        return ComparisonResponse(success=True, **_comparison_cache[cache_key])

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in comparison: {str(e)}")


# ============================================================================
# Cache Management
# ============================================================================


@router.delete("/cache/clear", tags=["Cache"])
async def clear_cache():
    """Clear analysis cache"""
    global _analysis_cache, _comparison_cache

    analysis_size = len(_analysis_cache)
    comparison_size = len(_comparison_cache)
    _analysis_cache = {}
    _comparison_cache = {}

    return {
        "success": True,
        "message": f"Cleared {analysis_size + comparison_size} cached items",
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/cache/info", tags=["Cache"])
async def cache_info():
    """Get cache information"""
    return {
        "success": True,
        "analysis_cache_size": len(_analysis_cache),
        "comparison_cache_size": len(_comparison_cache),
        "total_cached": len(_analysis_cache) + len(_comparison_cache),
        "timestamp": datetime.now().isoformat(),
    }