import pandas as pd
from datetime import datetime
from typing import Optional, Dict, List, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

# Import utilities
from routes.src.utils import (
    read_all_tracker_sheets,
    search_alerts_in_data,
)

# Create router
router = APIRouter()

# Global cache for data
_cached_data = None
_cache_timestamp = None


# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================


class SearchRequest(BaseModel):
    """Request model for search endpoint"""

    query: str = Field(..., description="Search query string", min_length=1)
    top_n: int = Field(5, ge=1, le=50, description="Number of top results to return")


class AlertMetadata(BaseModel):
    """Alert metadata structure"""

    rule_number: str = "N/A"
    alert_name: str = "N/A"
    incident: str = "N/A"
    priority: str = "N/A"
    type: str = "N/A"
    connector: str = "N/A"


class AlertInfo(BaseModel):
    """Alert information structure"""

    title: str
    rule_number: str
    alert_name: str
    metadata: Dict[str, Any] = {}


class SearchResponse(BaseModel):
    """Response model for search endpoint"""

    success: bool
    query: str
    total_found: int
    alerts: List[AlertInfo]
    timestamp: str


class SearchAlertStatusResponse(BaseModel):
    """Response model for search alert status check"""

    status: str
    timestamp: str
    data_loaded: bool
    cache_timestamp: Optional[str] = None
    total_records: int = 0


class LoadDataResponse(BaseModel):
    """Response model for load data endpoint"""

    success: bool
    total_incidents: int
    message: str
    timestamp: str


class AlertDetailsResponse(BaseModel):
    """Response model for alert details"""

    success: bool
    alert: Dict[str, Any]


class SelectAlertRequest(BaseModel):
    """Request model for select alert endpoint"""

    selected_alert: Dict[str, Any] = Field(..., description="Alert data to save")
    search_query: Optional[str] = Field(None, description="Original search query")
    all_alerts: Optional[List[str]] = Field(None, description="All alerts from search")


class SelectAlertResponse(BaseModel):
    """Response model for select alert endpoint"""

    success: bool
    message: str


class ErrorResponse(BaseModel):
    """Standard error response"""

    success: bool = False
    error: str
    detail: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================


def get_tracker_data(force_reload: bool = False) -> pd.DataFrame:
    """
    Load and cache tracker data

    Args:
        force_reload: Force reload data from files

    Returns:
        DataFrame with tracker data

    Raises:
        HTTPException: If data loading fails
    """
    global _cached_data, _cache_timestamp

    if force_reload or _cached_data is None:
        try:
            _cached_data = read_all_tracker_sheets("data")
            _cache_timestamp = datetime.now()
            print(f"✅ Loaded {len(_cached_data)} records from tracker sheets")
            return _cached_data
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Error loading tracker data: {str(e)}"
            )

    return _cached_data


# ============================================================================
# API Endpoints
# ============================================================================


@router.get(
    "/status",  # CHANGED from /health to /status to avoid conflict
    response_model=SearchAlertStatusResponse,
    summary="Search alert status check",
    description="Check if the search alert service is healthy and data is loaded",
)
async def search_alert_status():
    """
    Status check endpoint for search alert service

    Returns status, data loading state, and cache information
    """
    return SearchAlertStatusResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        data_loaded=_cached_data is not None,
        cache_timestamp=_cache_timestamp.isoformat() if _cache_timestamp else None,
        total_records=len(_cached_data) if _cached_data is not None else 0,
    )


@router.post(
    "/load-data",
    response_model=LoadDataResponse,
    summary="Load tracker data",
    description="Load or reload security tracker data from the data directory",
)
async def load_data():
    """
    Load or reload tracker data from files

    This endpoint forces a reload of all tracker sheets from the data directory.
    Use this when new data files are added or existing files are updated.

    Returns:
        LoadDataResponse with success status and incident count
    """
    try:
        data = get_tracker_data(force_reload=True)

        return LoadDataResponse(
            success=True,
            total_incidents=len(data),
            message=f"Successfully loaded {len(data)} incidents from tracker sheets",
            timestamp=datetime.now().isoformat(),
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Unexpected error loading data: {str(e)}"
        )


@router.post(
    "/search",
    response_model=SearchResponse,
    summary="Search alerts",
    description="Search for security alerts based on query string with intelligent matching",
)
async def search_alerts(request: SearchRequest):
    """
    Search for security alerts based on query

    This endpoint searches across multiple fields including:
    - Rule numbers and names
    - Alert descriptions
    - Incident types
    - Resolver comments
    - Data connectors

    Args:
        request: SearchRequest with query and top_n parameters

    Returns:
        SearchResponse with matching alerts and metadata
    """
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query parameter cannot be empty")

    # Get cached data
    tracker_data = get_tracker_data()

    if tracker_data.empty:
        raise HTTPException(
            status_code=500,
            detail="No tracker data available. Please load data first using /load-data endpoint.",
        )

    # Search for alerts
    try:
        alerts_list = search_alerts_in_data(
            tracker_data, request.query, top_n=request.top_n
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during search: {str(e)}")

    # Process each alert and add metadata
    alerts_with_info = []

    for alert_dict in alerts_list:
        # Handle both dict and string formats for backward compatibility
        if isinstance(alert_dict, dict):
            alert_title = alert_dict.get("full_rule", str(alert_dict))
            rule_number = alert_dict.get("rule_number", "N/A")
            alert_name = alert_dict.get("alert_name", "N/A")
            incident = alert_dict.get("incident_no", "N/A")
        else:
            # Fallback for string format
            alert_title = str(alert_dict)
            rule_number = "N/A"
            alert_name = "N/A"
            incident = "N/A"

        alert_info = AlertInfo(
            title=alert_title,
            rule_number=rule_number,
            alert_name=alert_name,
            metadata={},
        )

        # Enrich with incident details from tracker data
        if incident != "N/A":
            try:
                incident_row = tracker_data[
                    tracker_data["incident_no"].astype(str).str.strip()
                    == str(incident).strip()
                ]

                if not incident_row.empty:
                    info = incident_row.iloc[0]
                    alert_info.metadata = {
                        "rule_number": rule_number,
                        "alert_name": alert_name,
                        "incident": incident,
                        "priority": str(info.get("priority", "N/A")),
                        "type": str(info.get("alert_incident", "N/A")),
                        "connector": str(info.get("data_connector", "N/A")),
                        "status": str(info.get("status", "N/A")),
                        "shift_engineer": str(info.get("shift_engineer", "N/A")),
                        "reported_time": str(info.get("reported_time_stamp", "N/A")),
                        "responded_time": str(info.get("responded_time_stamp", "N/A")),
                        "mttd_mins": str(info.get("mttd_mins", "N/A")),
                        "mttr_mins": str(info.get("mttr_mins", "N/A")),
                    }
            except Exception as e:
                print(f"⚠️ Error processing incident {incident}: {str(e)}")

        alerts_with_info.append(alert_info)

    return SearchResponse(
        success=True,
        query=request.query,
        total_found=len(alerts_with_info),
        alerts=alerts_with_info,
        timestamp=datetime.now().isoformat(),
    )


@router.get(
    "/alert/{alert_index}/details",
    response_model=AlertDetailsResponse,
    summary="Get alert details",
    description="Get detailed information about a specific alert by its index in search results",
)
async def get_alert_details(
    alert_index: int,
    query: str = Query(..., description="Original search query used"),
    top_n: int = Query(
        5, ge=1, le=50, description="Number of results that were returned"
    ),
):
    """
    Get detailed information about a specific alert

    This endpoint retrieves comprehensive details for a specific alert
    identified by its index in the search results.

    Args:
        alert_index: Zero-based index of the alert
        query: Original search query
        top_n: Number of results that were searched

    Returns:
        AlertDetailsResponse with complete alert information
    """
    tracker_data = get_tracker_data()

    try:
        alerts_list = search_alerts_in_data(tracker_data, query, top_n=top_n)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving alerts: {str(e)}"
        )

    if alert_index >= len(alerts_list):
        raise HTTPException(
            status_code=404,
            detail=f"Alert index {alert_index} out of range. Total alerts found: {len(alerts_list)}",
        )

    alert_data = alerts_list[alert_index]

    # Handle both dict and string formats
    if isinstance(alert_data, dict):
        alert_title = alert_data.get("full_rule", str(alert_data))
        rule_number = alert_data.get("rule_number", "N/A")
        alert_name = alert_data.get("alert_name", "N/A")
        incident = alert_data.get("incident_no", "Unknown")
    else:
        alert_title = str(alert_data)
        parts = alert_title.split(" - ")
        rule_number = parts[0].strip() if parts else "Unknown"
        alert_name = parts[1].strip() if len(parts) > 1 else alert_title
        incident = "Unknown"

    # Get comprehensive incident details
    incident_row = tracker_data[
        tracker_data["incident_no"].astype(str).str.strip() == str(incident).strip()
    ]

    details = {
        "title": alert_title,
        "rule_number": rule_number,
        "alert_name": alert_name,
        "incident": incident,
        "metadata": {},
    }

    if not incident_row.empty:
        info = incident_row.iloc[0].to_dict()

        # Convert non-serializable types
        for key, value in info.items():
            if pd.isna(value):
                info[key] = None
            elif isinstance(value, (pd.Timestamp, datetime)):
                info[key] = value.isoformat()
            else:
                info[key] = str(value)

        details["metadata"] = info

    return AlertDetailsResponse(success=True, alert=details)


@router.post(
    "/select",
    response_model=SelectAlertResponse,
    summary="Select an alert",
    description="Mark an alert as selected and optionally save it for further processing",
)
async def select_alert(request: SelectAlertRequest):
    """
    Select and save an alert

    This endpoint is used to mark an alert as selected by the user.
    Can be extended to save selections to a database or file.

    Args:
        request: SelectAlertRequest with alert data

    Returns:
        SelectAlertResponse with success confirmation
    """
    if not request.selected_alert:
        raise HTTPException(status_code=400, detail="Selected alert data is required")

    # TODO: Add logic to save selected alert to database or file
    # For now, we just acknowledge the selection

    print(f"✅ Alert selected: {request.selected_alert.get('title', 'Unknown')}")
    if request.search_query:
        print(f"   Search query: {request.search_query}")

    return SelectAlertResponse(success=True, message="Alert selected successfully")
