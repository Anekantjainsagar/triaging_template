"""
Historical Analysis Component - Updated for API Integration
Displays historical incident data from API responses
"""

import streamlit as st
import pandas as pd
from datetime import datetime


def display_historical_analysis_tab(data):
    """
    Display historical analysis tab with incident data from API

    Args:
        data: List of dict records from API (historical incident data)
    """

    if not data:
        st.warning("No historical data available for this rule.")
        return

    # Convert API data (list of dicts) to DataFrame
    df = pd.DataFrame(data)

    st.markdown("### 📊 Historical Incident Analysis")
    st.markdown(f"**Total Incidents:** {len(df)}")

    # Display summary metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if "priority" in df.columns:
            critical_count = df[
                df["priority"].astype(str).str.upper() == "CRITICAL"
            ].shape[0]
            st.metric("Critical Alerts", critical_count)
        else:
            st.metric("Total Incidents", len(df))

    with col2:
        if "status" in df.columns:
            resolved = df[df["status"].astype(str).str.upper() == "RESOLVED"].shape[0]
            st.metric("Resolved", resolved)
        else:
            st.metric("Records", len(df))

    with col3:
        if "mttd_mins" in df.columns:
            try:
                avg_mttd = pd.to_numeric(df["mttd_mins"], errors="coerce").mean()
                st.metric(
                    "Avg MTTD",
                    f"{avg_mttd:.1f} mins" if not pd.isna(avg_mttd) else "N/A",
                )
            except:
                st.metric("Avg MTTD", "N/A")
        else:
            st.metric("Data Points", len(df.columns))

    with col4:
        if "mttr_mins" in df.columns:
            try:
                avg_mttr = pd.to_numeric(df["mttr_mins"], errors="coerce").mean()
                st.metric(
                    "Avg MTTR",
                    f"{avg_mttr:.1f} mins" if not pd.isna(avg_mttr) else "N/A",
                )
            except:
                st.metric("Avg MTTR", "N/A")
        else:
            st.metric(
                "Sources",
                (
                    df.get("source_file", pd.Series()).nunique()
                    if "source_file" in df.columns
                    else 1
                ),
            )

    st.markdown("---")

    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📋 Incident List", "📈 Trends", "📊 Raw Data"])

    with tab1:
        display_incident_list(df)

    with tab2:
        display_trends(df)

    with tab3:
        display_raw_data(df)


def display_incident_list(df):
    """Display formatted incident list"""
    st.markdown("#### Recent Incidents")

    # Select relevant columns for display
    display_columns = []
    preferred_columns = [
        "incident_no",
        "rule_number",
        "alert_name",
        "priority",
        "status",
        "reported_time_stamp",
        "shift_engineer",
        "mttd_mins",
        "mttr_mins",
        "data_connector",
    ]

    for col in preferred_columns:
        if col in df.columns:
            display_columns.append(col)

    if not display_columns:
        display_columns = list(df.columns[:10])  # Show first 10 columns

    # Display as formatted cards
    for idx, row in df.iterrows():
        with st.expander(
            f"🔔 Incident: {row.get('incident_no', idx)} - {row.get('status', 'Unknown').upper()}",
            expanded=False,
        ):
            col1, col2 = st.columns(2)

            with col1:
                for i, col in enumerate(display_columns[: len(display_columns) // 2]):
                    value = row.get(col, "N/A")
                    st.write(f"**{col.replace('_', ' ').title()}:** {value}")

            with col2:
                for col in display_columns[len(display_columns) // 2 :]:
                    value = row.get(col, "N/A")
                    st.write(f"**{col.replace('_', ' ').title()}:** {value}")


def display_trends(df):
    """Display trend analysis"""
    st.markdown("#### Trend Analysis")

    # Priority distribution
    if "priority" in df.columns:
        st.markdown("##### Priority Distribution")
        priority_counts = df["priority"].value_counts()
        st.bar_chart(priority_counts)

    # Status distribution
    if "status" in df.columns:
        st.markdown("##### Status Distribution")
        status_counts = df["status"].value_counts()
        st.bar_chart(status_counts)

    # Time-based trends
    if "reported_time_stamp" in df.columns:
        st.markdown("##### Incidents Over Time")
        try:
            df_time = df.copy()
            df_time["reported_time"] = pd.to_datetime(
                df_time["reported_time_stamp"], errors="coerce"
            )
            df_time = df_time.dropna(subset=["reported_time"])

            if not df_time.empty:
                df_time["date"] = df_time["reported_time"].dt.date
                daily_counts = df_time.groupby("date").size()
                st.line_chart(daily_counts)
            else:
                st.info("No valid timestamp data for time-based analysis")
        except Exception as e:
            st.warning(f"Could not generate time-based trends: {str(e)}")

    # Response time analysis
    col1, col2 = st.columns(2)

    with col1:
        if "mttd_mins" in df.columns:
            st.markdown("##### MTTD Distribution")
            try:
                mttd_values = pd.to_numeric(df["mttd_mins"], errors="coerce").dropna()
                if not mttd_values.empty:
                    st.bar_chart(mttd_values.value_counts().sort_index())
                else:
                    st.info("No MTTD data available")
            except:
                st.info("Could not process MTTD data")

    with col2:
        if "mttr_mins" in df.columns:
            st.markdown("##### MTTR Distribution")
            try:
                mttr_values = pd.to_numeric(df["mttr_mins"], errors="coerce").dropna()
                if not mttr_values.empty:
                    st.bar_chart(mttr_values.value_counts().sort_index())
                else:
                    st.info("No MTTR data available")
            except:
                st.info("Could not process MTTR data")


def display_raw_data(df):
    """Display raw data table"""
    st.markdown("#### Raw Incident Data")

    # Data info
    st.write(f"**Total Records:** {len(df)}")
    st.write(f"**Columns:** {len(df.columns)}")

    # Column selector
    all_columns = list(df.columns)
    selected_columns = st.multiselect(
        "Select columns to display",
        all_columns,
        default=all_columns[:10] if len(all_columns) > 10 else all_columns,
    )

    if selected_columns:
        # Display dataframe
        st.dataframe(df[selected_columns], width="stretch", height=400)

        # Download options
        col1, col2, col3 = st.columns([1, 1, 1])

        with col2:
            csv = df[selected_columns].to_csv(index=False)
            st.download_button(
                label="📥 Download as CSV",
                data=csv,
                file_name=f"historical_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                width="stretch",
            )
    else:
        st.info("Please select at least one column to display")
