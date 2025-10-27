import requests
import streamlit as st
from typing import Dict, List, Any


class SummaryAPIClient:
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
