import time
import logging
import requests
import streamlit as st
from typing import Dict, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnalyzerAPIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize API client with retry configuration"""
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "SOC-Client/1.0",
            }
        )
        self.max_retries = 3
        self.timeout = 30

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures session is closed"""
        self.close()

    def close(self):
        """Close the session to prevent resource leaks"""
        if hasattr(self, 'session') and self.session:
            self.session.close()

    def _retry_request(
        self, method: str, url: str, **kwargs
    ) -> Optional[requests.Response]:
        """Execute request with retry logic"""
        for attempt in range(self.max_retries):
            response = None
            try:
                if method.upper() == "GET":
                    response = self.session.get(url, timeout=self.timeout, **kwargs)
                elif method.upper() == "POST":
                    response = self.session.post(url, timeout=self.timeout, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                response.raise_for_status()
                return response

            except requests.exceptions.Timeout:
                if response:
                    response.close()
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}")
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                continue

            except requests.exceptions.ConnectionError:
                if response:
                    response.close()
                logger.warning(
                    f"Connection error on attempt {attempt + 1}/{self.max_retries}"
                )
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                continue

            except requests.exceptions.RequestException as e:
                if response:
                    response.close()
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2**attempt)
                continue

        raise requests.exceptions.ConnectionError(
            f"Failed to connect after {self.max_retries} attempts"
        )

    def health_check(self) -> Dict[str, Any]:
        """Check API health with error handling"""
        try:
            response = self._retry_request("GET", f"{self.base_url}/analyzer/status")
            return response.json()
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "soc_analyzer_loaded": False,
                "alert_analyzer_loaded": False,
            }

    def analyze_alert(self, alert_name: str, alert_description: Optional[str] = None) -> Dict[str, Any]:
        """Analyze alert with timeout handling and undefined check"""

        # HANDLE UNDEFINED/NULL VALUES
        if alert_name is None or alert_name == "undefined" or not alert_name:
            logger.error("Alert name is undefined or empty")
            return {
                "success": False,
                "error": "Alert name cannot be empty or undefined. Please select a valid alert.",
                "alert_name": alert_name,
            }

        # Ensure it's a string
        alert_name = str(alert_name).strip()
        alert_description = str(alert_description).strip() if alert_description else None

        if not alert_name:
            return {
                "success": False,
                "error": "Alert name is empty after processing",
            }

        try:
            logger.info(f"Analyzing alert: {alert_name}")
            if alert_description:
                logger.info(f"With description: {alert_description[:100]}...")

            # Prepare payload with both title and description
            payload = {"alert_name": alert_name}
            if alert_description:
                payload["alert_description"] = alert_description

            # Use longer timeout for analysis
            response = self.session.post(
                f"{self.base_url}/analyzer/analyze",
                json=payload,
                timeout=180,  # 3 minutes
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logger.error("Analysis timeout - API taking too long")
            return {
                "success": False,
                "error": "Analysis timeout. The API is processing your request but took longer than expected. "
                "This may indicate the backend is under heavy load. Please try again.",
            }
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to analyzer API")
            return {
                "success": False,
                "error": "Cannot connect to SOC analyzer backend. "
                "Please ensure the backend service is running on http://localhost:8000",
            }
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return {"success": False, "error": "Analysis failed due to an internal error"}

    def get_historical_data(self, rule_name: str) -> Dict[str, Any]:
        """Get historical data with fallback"""
        try:
            response = self.session.post(
                f"{self.base_url}/analyzer/historical-data",
                json={"rule_name": rule_name},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"No historical data for rule: {rule_name}")
                return {
                    "success": False,
                    "error": f"No historical data found for: {rule_name}",
                    "data": [],
                }
            raise

        except Exception as e:
            logger.error(f"Historical data error: {str(e)}")
            return {"success": False, "error": "Failed to retrieve historical data", "data": []}

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

    def get_system_stats(self) -> Dict[str, Any]:
        """
        Get system statistics

        Returns:
            Dict with total_records, unique_rules, and data_sources
        """
        response = None
        try:
            response = self.session.get(f"{self.base_url}/analyzer/stats", timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if response:
                response.close()
            return {"success": False, "error": str(e)}

    def system_health(self) -> Dict[str, Any]:
        """
        Check system-wide health

        Returns:
            Dict with overall system health status
        """
        response = None
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if response:
                response.close()
            return {"status": "error", "error": str(e)}


# ============================================================================
# Streamlit Integration
# ============================================================================


def get_analyzer_client(base_url: str = "http://localhost:8000") -> AnalyzerAPIClient:
    """
    Get analyzer API client instance for Streamlit

    Args:
        base_url: Base URL of the FastAPI server

    Returns:
        AnalyzerAPIClient instance
    """
    return AnalyzerAPIClient(base_url)
