import streamlit as st


def apply_custom_css():
    """Apply custom CSS styling"""
    st.markdown(
        """
    <style>
        .main-header {
            font-size: 2.5rem;
            color: #2c3e50;
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


def apply_predictions_css():
    st.markdown(
        """
        <style>
        .main-header {
            font-size: 2.5rem;
            font-weight: bold;
            color: #1f2937;
            margin-bottom: 1rem;
        }
        .risk-critical {
            background-color: #fee2e2;
            border-left: 4px solid #dc2626;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        .risk-high {
            background-color: #fed7aa;
            border-left: 4px solid #ea580c;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        .risk-medium {
            background-color: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        .risk-low {
            background-color: #d1fae5;
            border-left: 4px solid #10b981;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        .mitre-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin: 1rem 0;
        }
        .attack-chain-box {
            background-color: #1f2937;
            color: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin: 1rem 0;
        }
        .sub-technique-badge {
            background-color: #3b82f6;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.875rem;
            display: inline-block;
            margin: 0.25rem;
        }
        .technique-hierarchy {
            padding-left: 1.5rem;
            border-left: 3px solid #3b82f6;
            margin: 0.5rem 0;
        }
        
        /* MITRE Matrix Styles */
        .mitre-matrix-container {
            overflow-x: auto;
            margin: 2rem 0;
        }
        .mitre-matrix {
            border-collapse: collapse;
            width: 100%;
            min-width: 1200px;
            font-size: 0.75rem;
        }
        .mitre-matrix th {
            background-color: #1e3a8a;
            color: white;
            padding: 0.5rem;
            text-align: center;
            font-weight: bold;
            border: 1px solid #1e40af;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        .mitre-matrix td {
            padding: 0.25rem 0.5rem;
            border: 1px solid #e5e7eb;
            vertical-align: top;
            background-color: #f9fafb;
            min-height: 80px;
            font-size: 0.7rem;
        }
        .technique-cell {
            cursor: pointer;
            transition: all 0.2s;
            margin: 2px 0;
            padding: 4px 6px;
            border-radius: 3px;
            font-size: 0.7rem;
            line-height: 1.2;
        }
        .technique-cell:hover {
            transform: scale(1.02);
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .severity-red {
            background-color: #dc2626;
            color: white;
            font-weight: bold;
        }
        .severity-amber {
            background-color: #f59e0b;
            color: white;
            font-weight: bold;
        }
        .severity-green {
            background-color: #10b981;
            color: white;
            font-weight: bold;
        }
        .severity-blue {
            background-color: #3b82f6;
            color: white;
            font-weight: bold;
        }
        .severity-grey {
            background-color: #9ca3af;
            color: white;
        }
        .technique-id {
            font-size: 0.65rem;
            opacity: 0.8;
        }
        .info-tooltip {
            background-color: #eff6ff;
            border-left: 4px solid #3b82f6;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 1rem 0;
            font-size: 0.9rem;
        }
        .timeline-item {
            background-color: #f8fafc;
            border-left: 3px solid #3b82f6;
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 0 0.5rem 0.5rem 0;
        }
        .procedure-box {
            background-color: #fef3c7;
            border: 1px solid #fbbf24;
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        </style>
    """,
        unsafe_allow_html=True,
    )
