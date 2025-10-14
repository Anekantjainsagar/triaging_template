"""
FastAPI Client for SOC Analyzer Backend
Client for interacting with the SOC Intelligence API
"""

import requests
import streamlit as st
from typing import Optional, Dict, List, Any


class AnalyzerAPIClient:
    """Client for interacting with the SOC Analyzer FastAPI Backend"""

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
        Check if SOC analyzer API is healthy

        Returns:
            Dict with status, timestamp, analyzer loading state, and total_records
        """
        try:
            response = self.session.get(f"{self.base_url}/analyzer/health", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "soc_analyzer_loaded": False,
                "alert_analyzer_loaded": False,
                "total_records": 0,
            }

    def load_data(self) -> Dict[str, Any]:
        """
        Load or reload SOC analyzer data

        Returns:
            Dict with success status, total_records, unique_rules, message, and timestamp
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyzer/load-data",
                timeout=60,  # Longer timeout for data loading
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def get_rule_suggestions(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        """
        Get rule suggestions based on query

        Args:
            query: Search query string
            top_k: Number of suggestions to return (default: 5, max: 20)

        Returns:
            Dict with success, query, total_found, suggestions list, and timestamp
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyzer/suggestions",
                json={"query": query, "top_k": min(top_k, 20)},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e), "suggestions": []}

    def analyze_alert(self, alert_name: str) -> Dict[str, Any]:
        """
        Analyze alert with AI-powered threat intelligence

        Args:
            alert_name: Name of the alert/rule to analyze

        Returns:
            Dict with success status and detailed analysis
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyzer/analyze",
                json={"alert_name": alert_name},
                timeout=1800,  # 3 minutes timeout for AI analysis
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def get_historical_data(self, rule_name: str) -> Dict[str, Any]:
        """
        Get historical incident data for a rule

        Args:
            rule_name: Name of the rule to get historical data

        Returns:
            Dict with success status and historical incident data
        """
        try:
            response = self.session.post(
                f"{self.base_url}/analyzer/historical-data",
                json={"rule_name": rule_name},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def get_system_stats(self) -> Dict[str, Any]:
        """
        Get system statistics

        Returns:
            Dict with total_records, unique_rules, and data_sources
        """
        try:
            response = self.session.get(f"{self.base_url}/analyzer/stats", timeout=10)
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
def get_analyzer_client(base_url: str = "http://localhost:8000") -> AnalyzerAPIClient:
    """
    Get cached analyzer API client instance for Streamlit

    Args:
        base_url: Base URL of the FastAPI server

    Returns:
        Cached AnalyzerAPIClient instance
    """
    return AnalyzerAPIClient(base_url)


# ============================================================================
# Usage Example
# ============================================================================

if __name__ == "__main__":
    # Example usage
    client = AnalyzerAPIClient()

    # Check if API is available
    print("Checking API availability...")
    if client.is_api_available():
        print("✅ API is available")

        # Get API info
        info = client.get_api_info()
        print(f"\n📋 API Info: {info}")

        # Health check
        health = client.health_check()
        print(f"\n💚 Health Status: {health}")

        # Get system stats
        stats = client.get_system_stats()
        if stats.get("success"):
            print(f"\n📊 System Stats:")
            print(f"  Total Records: {stats.get('total_records')}")
            print(f"  Unique Rules: {stats.get('unique_rules')}")
            print(f"  Data Sources: {stats.get('data_sources')}")

        # Example search
        print("\n🔍 Searching for 'conditional access' rules...")
        results = client.get_rule_suggestions("conditional access", top_k=3)
        if results.get("success"):
            print(f"Found {results.get('total_found')} suggestions")
            for i, suggestion in enumerate(results.get("suggestions", [])):
                print(f"  {i+1}. {suggestion.get('rule')}")
                print(
                    f"     Score: {suggestion.get('score'):.2%} | Incidents: {suggestion.get('incident_count')}"
                )
        else:
            print(f"Search failed: {results.get('error')}")

    else:
        print("❌ API is not available. Please start the FastAPI server.")
        print("Run: uvicorn fastapi_backend:app --reload --host 0.0.0.0 --port 8000")
