"""
FastAPI Client for Predictions & MITRE Analysis Backend
Client for interacting with the Investigation Analysis API
"""

import requests
import streamlit as st
from typing import Optional, Dict, List, Any, BinaryIO
import json
from io import BytesIO


class PredictionsAPIClient:
    """Client for interacting with the Predictions & MITRE Analysis FastAPI Backend"""

    def __init__(
        self, base_url: str = "http://localhost:8000/predictions", api_key: str = ""
    ):
        """
        Initialize API client

        Args:
            base_url: Base URL of the FastAPI server (default: http://localhost:8000)
            api_key: Google API key for analysis (optional)
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    # ========================================================================
    # Health & Status Endpoints
    # ========================================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Check if Predictions API is healthy

        Returns:
            Dict with status, service info, and timestamp
        """
        try:
            response = self.session.get(f"http://localhost:8000/health", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "service": "Predictions & MITRE Analysis API",
            }

    def analyzer_status(self) -> Dict[str, Any]:
        """
        Check analyzer service status

        Returns:
            Dict with analyzer loading state and statistics
        """
        try:
            response = self.session.get(f"{self.base_url}/status", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "analyzer_loaded": False}

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get API usage statistics

        Returns:
            Dict with analysis statistics and classifications
        """
        try:
            # FIXED: Changed from /status/statistics to /statistics
            response = self.session.get(f"{self.base_url}/statistics", timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def is_api_available(self) -> bool:
        """
        Quick check if API is reachable

        Returns:
            True if API is available, False otherwise
        """
        try:
            response = self.session.get(f"http://localhost:8000/health", timeout=3)
            return response.status_code == 200
        except:
            return False

    # ========================================================================
    # Upload Endpoints
    # ========================================================================

    def upload_excel(self, file_path: str) -> Dict[str, Any]:
        """
        Upload investigation Excel file

        Args:
            file_path: Path to Excel file

        Returns:
            Dict with upload status, total rows, columns, and preview
        """
        try:
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = self.session.post(
                    f"{self.base_url}/upload/excel", files=files, timeout=30
                )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}
        except FileNotFoundError:
            return {"success": False, "error": f"File not found: {file_path}"}

    def upload_excel_bytes(self, file_bytes: BinaryIO, filename: str) -> Dict[str, Any]:
        """
        Upload investigation Excel file from bytes - COMPLETELY FIXED VERSION
        """
        try:
            # ✅ FIX: Read the bytes and create a fresh file object
            file_bytes.seek(0)
            file_content = file_bytes.read()

            # ✅ FIX: Create new BytesIO object for the request
            file_for_upload = BytesIO(file_content)

            # ✅ FIX: Prepare files with correct encoding
            files = {
                "file": (
                    filename,
                    file_for_upload,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            }

            # ✅ FIX: Use the base URL without /predictions for upload endpoint
            upload_url = self.base_url + "/upload/excel"

            print(f"📤 Uploading to: {upload_url}")
            print(f"📁 File: {filename}, Size: {len(file_content)} bytes")

            # ✅ FIX: Use requests directly with proper headers
            response = requests.post(upload_url, files=files, timeout=30)

            print(f"📥 Response status: {response.status_code}")

            if response.status_code == 422:
                error_detail = response.json()
                return {"success": False, "error": f"Validation error: {error_detail}"}
            elif response.status_code == 400:
                return {"success": False, "error": f"Bad Request: {response.text}"}
            elif response.status_code >= 500:
                return {"success": False, "error": f"Server Error: {response.text}"}

            response.raise_for_status()
            result = response.json()

            print(f"✅ Upload successful: {result}")

            # Ensure success field exists
            if "success" not in result:
                result["success"] = True

            return result

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Upload request timed out after 30 seconds",
            }
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Upload failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}

    def get_upload_preview(self) -> Dict[str, Any]:
        """
        Get preview of uploaded data

        Returns:
            Dict with preview data, total rows, and columns
        """
        try:
            response = self.session.get(f"{self.base_url}/upload/preview", timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    # ========================================================================
    # Analysis Endpoints
    # ========================================================================

    def analyze_initial(self, username: str) -> Dict[str, Any]:
        """
        Perform initial classification analysis

        Args:
            username: Username to analyze

        Returns:
            Dict with classification, risk level, confidence score, and summary
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyze/initial",
                json={"username": username},
                params={"api_key": self.api_key},
                timeout=120,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def analyze_mitre(self, username: str) -> Dict[str, Any]:
        """
        Perform MITRE ATT&CK analysis

        Args:
            username: Username to analyze

        Returns:
            Dict with comprehensive MITRE analysis including techniques and sub-techniques
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyze/mitre",
                json={"username": username},
                params={"api_key": self.api_key},
                timeout=300,  # 5 minutes for LLM processing
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def analyze_complete(self, username: str) -> Dict[str, Any]:
        """
        Perform complete investigation analysis

        This is the primary analysis endpoint combining:
        - Initial classification
        - MITRE ATT&CK mapping with sub-techniques
        - Executive summary
        - Geographic risk assessment

        Args:
            username: Username to analyze

        Returns:
            Dict with comprehensive analysis report
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyze/complete",
                json={"username": username},
                params={"api_key": self.api_key},
                timeout=300,  # 5 minutes for complete analysis
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    # ========================================================================
    # Cache Management Endpoints
    # ========================================================================

    def clear_cache(self) -> Dict[str, Any]:
        """
        Clear analysis cache

        Returns:
            Dict with success status and cache size cleared
        """
        try:
            response = self.session.delete(f"{self.base_url}/cache/clear", timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def cache_info(self) -> Dict[str, Any]:
        """
        Get cache information

        Returns:
            Dict with cached analyses count and keys
        """
        try:
            response = self.session.get(f"{self.base_url}/cache/info", timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def get_api_info(self) -> Dict[str, Any]:
        """
        Get API information and available routes

        Returns:
            Dict with API name, version, status, and available routes
        """
        try:
            response = self.session.get(f"{self.base_url}", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def set_api_key(self, api_key: str):
        """
        Update API key for analysis

        Args:
            api_key: Google API key
        """
        self.api_key = api_key

    def set_base_url(self, base_url: str):
        """
        Update base URL

        Args:
            base_url: New base URL
        """
        self.base_url = base_url.rstrip("/")


# ============================================================================
# Streamlit Integration
# ============================================================================


@st.cache_resource
def get_predictions_client(
    base_url: str = "http://localhost:8000/predictions", api_key: str = ""
) -> PredictionsAPIClient:
    """
    Get cached predictions API client instance for Streamlit

    Args:
        base_url: Base URL of the FastAPI server
        api_key: Google API key for analysis

    Returns:
        Cached PredictionsAPIClient instance
    """
    return PredictionsAPIClient("http://localhost:8000/predictions", api_key)


@st.cache_data
def cache_analysis_result(username: str, analysis_data: Dict[str, Any]) -> str:
    """
    Cache analysis result in Streamlit

    Args:
        username: Username analyzed
        analysis_data: Complete analysis data

    Returns:
        Cache key
    """
    cache_key = f"{username}_{hash(str(analysis_data))}"
    return cache_key


# ============================================================================
# Utility Functions for Streamlit Integration
# ============================================================================


def validate_api_connection(base_url: str) -> tuple[bool, str]:
    """
    Validate connection to predictions API

    Args:
        base_url: API base URL

    Returns:
        Tuple of (is_connected, message)
    """
    client = PredictionsAPIClient("http://localhost:8000/predictions")
    if client.is_api_available():
        return True, "✅ Connected to Predictions API"
    else:
        return False, "❌ Cannot connect to Predictions API"


def format_analysis_for_display(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format analysis result for Streamlit display

    Args:
        analysis: Raw analysis from API

    Returns:
        Formatted analysis data
    """
    if not analysis.get("success"):
        return {"error": analysis.get("error", "Unknown error")}

    return {
        "classification": analysis.get("initial_analysis", {}).get("classification"),
        "risk_level": analysis.get("initial_analysis", {}).get("risk_level"),
        "confidence": analysis.get("initial_analysis", {}).get("confidence_score"),
        "summary": analysis.get("initial_analysis", {}).get("summary"),
        "mitre_analysis": analysis.get("mitre_attack_analysis"),
        "executive_summary": analysis.get("executive_summary"),
        "geographic_risk": analysis.get("geographic_risk"),
    }


def export_analysis_json(
    analysis: Dict[str, Any], filename: str = "analysis.json"
) -> str:
    """
    Export analysis to JSON format

    Args:
        analysis: Analysis data
        filename: Output filename

    Returns:
        JSON string
    """
    return json.dumps(analysis, indent=2)
