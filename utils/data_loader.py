import streamlit as st
import pandas as pd
from src.utils import read_all_tracker_sheets, search_alerts_in_data


@st.cache_data
def load_tracker_data():
    """Load and cache all tracker sheet data."""
    try:
        df = read_all_tracker_sheets("data")
        return df
    except Exception as e:
        st.error(f"Error loading tracker data: {str(e)}")
        return pd.DataFrame()


def search_alerts(data, search_query, top_n=5):
    """Search for alerts in the data."""
    try:
        return search_alerts_in_data(data, search_query, top_n=top_n)
    except Exception as e:
        st.error(f"Error during search: {str(e)}")
        return []


@st.cache_resource
def get_crew():
    """Initialize and cache the CrewAI instance."""
    from src.crew import TriagingCrew

    return TriagingCrew()
