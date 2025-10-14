"""
FastAPI Client for Security Alert Backend
Updated for FastAPI with /search-alert prefix routing
"""

import requests
import streamlit as st
from typing import Optional, Dict, List, Any


class AlertAPIClient:
    """Client for interacting with the Security Alert FastAPI Backend"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """
        Initialize API client

        Args:
            base_url: Base URL of the FastAPI server (default: http://localhost:8000)
        """
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Check if search alert API is healthy

        Returns:
            Dict with status, timestamp, data_loaded, cache_timestamp, and total_records
        """
        try:
            response = self.session.get(
                f"{self.base_url}/search-alert/status",
                timeout=5,  # CHANGED from /health to /status
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "data_loaded": False,
                "total_records": 0,
            }

    def load_data(self) -> Dict[str, Any]:
        """
        Load or reload tracker data

        Returns:
            Dict with success status, total_incidents, message, and timestamp
        """
        try:
            response = self.session.post(
                f"{self.base_url}/search-alert/load-data", timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def search_alerts(self, query: str, top_n: int = 5) -> Dict[str, Any]:
        """
        Search for alerts based on query

        Args:
            query: Search query string
            top_n: Number of top results to return (default: 5, max: 50)

        Returns:
            Dict with success, query, total_found, alerts list, and timestamp
        """
        try:
            response = self.session.post(
                f"{self.base_url}/search-alert/search",
                json={"query": query, "top_n": min(top_n, 50)},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e), "alerts": []}

    def get_alert_details(
        self, alert_index: int, query: str, top_n: int = 5
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific alert

        Args:
            alert_index: Index of the alert in search results (0-based)
            query: Original search query
            top_n: Number of results that were returned

        Returns:
            Dict with success status and detailed alert information
        """
        try:
            response = self.session.get(
                f"{self.base_url}/search-alert/alert/{alert_index}/details",
                params={"query": query, "top_n": top_n},
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def select_alert(
        self,
        selected_alert: Dict[str, Any],
        search_query: Optional[str] = None,
        all_alerts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Save or mark an alert as selected

        Args:
            selected_alert: Alert data to save (required)
            search_query: Original search query (optional)
            all_alerts: All alerts from search (optional)

        Returns:
            Dict with success status and message
        """
        try:
            payload = {"selected_alert": selected_alert}

            if search_query:
                payload["search_query"] = search_query

            if all_alerts:
                payload["all_alerts"] = all_alerts

            response = self.session.post(
                f"{self.base_url}/search-alert/select", json=payload, timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def get_api_info(self) -> Dict[str, Any]:
        """
        Get API information and available routes

        Returns:
            Dict with API name, version, status, documentation links, and available routes
        """
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def system_health(self) -> Dict[str, Any]:
        """
        Check system-wide health

        Returns:
            Dict with overall system health status
        """
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def is_api_available(self) -> bool:
        """
        Quick check if API is reachable

        Returns:
            True if API is available, False otherwise
        """
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=3)
            return response.status_code == 200
        except:
            return False


# ============================================================================
# Streamlit Integration
# ============================================================================


@st.cache_resource
def get_api_client(base_url: str = "http://localhost:8000") -> AlertAPIClient:
    """
    Get cached API client instance for Streamlit

    Args:
        base_url: Base URL of the FastAPI server

    Returns:
        Cached AlertAPIClient instance
    """
    return AlertAPIClient(base_url)
