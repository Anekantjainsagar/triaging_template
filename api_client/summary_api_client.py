import requests
import streamlit as st
from typing import Dict, List, Any


class SummaryAPIClient:
    """Client for interacting with the Summary Generation FastAPI Backend"""

    def __init__(self, base_url: str = "http://localhost:8000/summaries"):
        """
        Initialize API client

        Args:
            base_url: Base URL of the FastAPI server (default: http://localhost:8000/summaries)
        """
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    # ========================================================================
    # Summary Generation Endpoints
    # ========================================================================

    def generate_single_summary(
        self, section_name: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate AI summary for a single section

        Args:
            section_name: Name of the section (e.g., "Alert Classification")
            data: Dictionary containing metrics for the section

        Returns:
            Dict with success status, summary, and timestamp
        """
        try:
            response = self.session.post(
                f"{self.base_url}/generate/single",
                json={"section_name": section_name, "data": data},
                timeout=60,  # LLM generation can take time
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def generate_multiple_summaries(
        self, historical_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate AI summaries for all sections from historical data

        This is the main endpoint that takes raw incident data and returns
        summaries for all applicable sections.

        Args:
            historical_data: List of incident records (dict format)

        Returns:
            Dict with summaries, metrics, summary_data, and total_incidents
        """
        try:
            response = self.session.post(
                f"{self.base_url}/generate/multiple",
                json={"historical_data": historical_data},
                timeout=120,  # Multiple LLM calls
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    # ========================================================================
    # Cache Management Endpoints
    # ========================================================================

    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get information about summary cache

        Returns:
            Dict with cache statistics and keys
        """
        try:
            response = self.session.get(f"{self.base_url}/cache/info", timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def clear_cache(self) -> Dict[str, Any]:
        """
        Clear all cached summaries

        Returns:
            Dict with success status and cleared count
        """
        try:
            response = self.session.delete(f"{self.base_url}/cache/clear", timeout=10)
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
            Dict with API name, version, and available routes
        """
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def is_api_available(self) -> bool:
        """
        Quick check if API is reachable

        Returns:
            True if API is available, False otherwise
        """
        try:
            response = self.session.get(f"{self.base_url}/", timeout=3)
            return response.status_code == 200
        except:
            return False


# ============================================================================
# Streamlit Integration
# ============================================================================


@st.cache_resource
def get_summary_client(
    base_url: str = "http://localhost:8000/summaries",
) -> SummaryAPIClient:
    """
    Get cached summary API client instance for Streamlit

    Args:
        base_url: Base URL of the FastAPI server

    Returns:
        Cached SummaryAPIClient instance
    """
    return SummaryAPIClient(base_url)


# ============================================================================
# Helper Functions for Integration
# ============================================================================


def validate_summary_api_connection(base_url: str) -> tuple[bool, str]:
    """
    Validate connection to summary API

    Args:
        base_url: API base URL

    Returns:
        Tuple of (is_connected, message)
    """
    client = SummaryAPIClient(base_url)
    if client.is_api_available():
        return True, "✅ Connected to Summary API"
    else:
        return False, "❌ Cannot connect to Summary API"
