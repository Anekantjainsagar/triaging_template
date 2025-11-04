import streamlit as st
import pandas as pd
import hashlib
import json
from frontend.utils.alert_analysis.metrices import extract_detailed_metrics
from api_client.summary_api_client import get_summary_client


def convert_timestamps_to_str(data_df: pd.DataFrame) -> pd.DataFrame:
    """Convert all datetime/timestamp columns to strings for JSON serialization"""
    df_copy = data_df.copy()

    # Find all datetime columns
    datetime_columns = df_copy.select_dtypes(
        include=["datetime64", "datetime64[ns]"]
    ).columns

    # Convert to ISO format strings
    for col in datetime_columns:
        df_copy[col] = df_copy[col].astype(str)

    return df_copy


def display_historical_analysis_tab(data_df: pd.DataFrame):
    """Display streamlined historical data analysis tab with API-generated summaries"""

    # ✅ CREATE CACHE KEY FOR THIS SPECIFIC DATA
    data_hash = hashlib.md5(
        json.dumps(data_df.head().to_dict(), sort_keys=True, default=str).encode()
    ).hexdigest()
    cache_key = f"historical_analysis_{data_hash}"

    # ✅ CHECK IF ALREADY PROCESSED
    if cache_key in st.session_state:
        cached_data = st.session_state[cache_key]
        metrics = cached_data["metrics"]
        summary_data = cached_data["summary_data"]
        summaries = cached_data["summaries"]
    else:
        # ✅ FIRST TIME - Extract metrics and call API for summaries
        with st.spinner("📊 Analyzing historical data..."):
            metrics = extract_detailed_metrics(data_df)

            # 🔧 FIX: Convert timestamps to strings before serialization
            data_df_serializable = convert_timestamps_to_str(data_df)

            # Convert DataFrame to list of dicts for API
            historical_data = data_df_serializable.to_dict(orient="records")

            # Get summary client and generate summaries via API
            summary_client = get_summary_client()
            api_result = summary_client.generate_multiple_summaries(historical_data)

            if api_result.get("success"):
                summaries = api_result.get("summaries", {})
                summary_data = api_result.get("summary_data", {})

                # If API didn't return summary_data, extract it locally
                if not summary_data:
                    from backend.historical_analysis_backend import extract_summary_data

                    summary_data = extract_summary_data(metrics, data_df)
            else:
                # Fallback to local generation if API fails
                st.warning(
                    f"⚠️ API summary generation failed: {api_result.get('error')}. Using local generation."
                )
                from backend.historical_analysis_backend import (
                    generate_data_summary_with_llm,
                    extract_summary_data,
                )

                summary_data = extract_summary_data(metrics, data_df)
                summaries = {"classification": None, "vip": None, "response": None}

                # Generate summaries locally as fallback
                if "classification_analysis" in metrics:
                    summaries["classification"] = generate_data_summary_with_llm(
                        "Alert Classification",
                        summary_data.get("Alert Classification", {}),
                    )

                if "vip_analysis" in metrics:
                    summaries["vip"] = generate_data_summary_with_llm(
                        "VIP User Distribution",
                        summary_data.get("VIP User Distribution", {}),
                    )

                if "mttr_analysis" in metrics or "mttd_analysis" in metrics:
                    summaries["response"] = generate_data_summary_with_llm(
                        "Response Time Analysis",
                        summary_data.get("Response Time Analysis", {}),
                    )

        # ✅ CACHE EVERYTHING
        st.session_state[cache_key] = {
            "metrics": metrics,
            "summary_data": summary_data,
            "summaries": summaries,
        }

    # ========== DISPLAY SECTION (Uses Cached Data) ==========

    # Classification Breakdown
    if "False / True Positive" in data_df.columns:
        st.markdown("### 🎯 Alert Classification")

        # Display cached summary
        if summaries.get("Alert Classification"):
            st.info(summaries["Alert Classification"])

        # Standardize classification values
        fp_column = data_df["False / True Positive"].astype(str).str.strip().str.lower()
        fp_standardized = fp_column.replace(
            {
                "truepositive": "True Positive",
                "true positive": "True Positive",
                "falsepositive": "False Positive",
                "false positive": "False Positive",
                "benignpositive": "Benign Positive",
                "benign positive": "Benign Positive",
            }
        )

        classification_counts = fp_standardized.value_counts()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Incidents", f"{metrics['total_incidents']:,}")

        with col2:
            tp_count = classification_counts.get("True Positive", 0)
            st.metric(
                "True Positives",
                tp_count,
                delta=f"{tp_count/len(data_df)*100:.2f}% of total",
            )

        with col3:
            fp_count = classification_counts.get("False Positive", 0)
            st.metric(
                "False Positives",
                fp_count,
                delta=f"{fp_count/len(data_df)*100:.2f}% of total",
                delta_color="inverse",
            )

        with col4:
            bp_count = classification_counts.get("Benign Positive", 0)
            st.metric(
                "Benign Positives",
                bp_count,
                delta=f"{bp_count/len(data_df)*100:.2f}% of total",
            )

    st.markdown("---")

    # VIP User Analysis
    if "VIP Users " in data_df.columns:
        st.markdown("### 👤 VIP User Analysis")

        # Display cached summary
        if summaries.get("VIP User Distribution"):
            st.info(summaries["VIP User Distribution"])

        vip_column = data_df["VIP Users "].astype(str).str.strip().str.lower()
        vip_standardized = vip_column.replace(
            {"yes": "Yes", "no": "No", "y": "Yes", "n": "No"}
        )

        vip_counts = vip_standardized.value_counts()

        col1, col2 = st.columns(2)

        with col1:
            vip_yes = vip_counts.get("Yes", 0)
            st.metric(
                "VIP User Incidents",
                vip_yes,
                delta=f"{vip_yes/len(data_df)*100:.2f}% of total",
            )

        with col2:
            vip_no = vip_counts.get("No", 0)
            st.metric(
                "Non-VIP User Incidents",
                vip_no,
                delta=f"{vip_no/len(data_df)*100:.2f}% of total",
            )

    st.markdown("---")

    # Performance Summary
    st.markdown("### ⏱️ Response Time Analysis")

    # Display cached summary
    if summaries.get("Response Time Analysis"):
        st.info(summaries["Response Time Analysis"])

    col1, col2 = st.columns(2)

    with col1:
        if "mttr_analysis" in metrics:
            mttr = metrics["mttr_analysis"]
            st.markdown("**Resolution Time (MTTR):**")
            st.write(f"• Mean: {mttr['mean']:.2f} minutes")
            st.write(f"• Median: {mttr['median']:.2f} minutes")
            st.write(f"• 90th Percentile: {mttr['percentiles']['90th']:.2f} minutes")

    with col2:
        if "mttd_analysis" in metrics:
            mttd = metrics["mttd_analysis"]
            st.markdown("**Detection Time (MTTD):**")
            st.write(f"• Mean: {mttd['mean']:.2f} minutes")
            st.write(f"• Median: {mttd['median']:.2f} minutes")
            st.write(f"• Fast Detection (≤5 min): {mttd['fast_detection']} incidents")
