import streamlit as st


def apply_custom_css():
    """Apply custom CSS styling"""
    st.markdown(
        """
    <style>
        .main-header {
            font-size: 2.5rem;
            color: #2c3e50;
            text-align: center;
            margin-bottom: 2rem;
        }
        .section-header {
            color: #2c3e50;
            font-weight: bold;
            margin: 1.5rem 0 1rem 0;
        }
        .threat-intel-box {
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0.25rem;
        }
        .alert-context-header {
            color: #dc3545;
            font-size: 1.3rem;
            font-weight: bold;
            margin: 1rem 0;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding-left: 20px;
            padding-right: 20px;
        }
    </style>
    """,
        unsafe_allow_html=True,
    )
