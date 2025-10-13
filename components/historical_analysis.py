import streamlit as st
import pandas as pd
from utils.metrices import extract_detailed_metrics
from utils.generate_summaries import generate_data_summary_with_ollama, extract_summary_data


def display_historical_analysis_tab(data_df: pd.DataFrame):
    """Display streamlined historical data analysis tab with LLM-generated summaries"""

    # Extract metrics
    metrics = extract_detailed_metrics(data_df)
    
    # Extract data for summaries
    summary_data = extract_summary_data(metrics, data_df)
    
    # Classification Breakdown
    if "False / True Positive" in data_df.columns:
        st.markdown("### 🎯 Alert Classification")
        
        # Generate and display summary directly
        class_summary = generate_data_summary_with_ollama(
            "Alert Classification", 
            summary_data.get("Alert Classification", {})
        )
        st.info(class_summary)
        
        # Standardize classification values
        fp_column = data_df["False / True Positive"].astype(str).str.strip().str.lower()
        fp_standardized = fp_column.replace({
            'truepositive': 'True Positive',
            'true positive': 'True Positive',
            'falsepositive': 'False Positive',
            'false positive': 'False Positive',
            'benignpositive': 'Benign Positive',
            'benign positive': 'Benign Positive',
        })
        
        classification_counts = fp_standardized.value_counts()
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Incidents", f"{metrics['total_incidents']:,}")
            
        with col2:
            tp_count = classification_counts.get('True Positive', 0)
            st.metric("True Positives", tp_count, 
                     delta=f"{tp_count/len(data_df)*100:.2f}% of total")
        
        with col3:
            fp_count = classification_counts.get('False Positive', 0)
            st.metric("False Positives", fp_count,
                     delta=f"{fp_count/len(data_df)*100:.2f}% of total",
                     delta_color="inverse")
        
        with col4:
            bp_count = classification_counts.get('Benign Positive', 0)
            st.metric("Benign Positives", bp_count,
                     delta=f"{bp_count/len(data_df)*100:.2f}% of total")

    st.markdown("---")
    
    # VIP User Analysis
    if "VIP Users " in data_df.columns:
        st.markdown("### 👤 VIP User Analysis")
        
        # Generate and display summary directly
        vip_summary = generate_data_summary_with_ollama(
            "VIP User Distribution", 
            summary_data.get("VIP User Distribution", {})
        )
        st.info(vip_summary)
        
        vip_column = data_df["VIP Users "].astype(str).str.strip().str.lower()
        vip_standardized = vip_column.replace({
            'yes': 'Yes',
            'no': 'No',
            'y': 'Yes',
            'n': 'No'
        })
        
        vip_counts = vip_standardized.value_counts()
        
        col1, col2 = st.columns(2)
        
        with col1:
            vip_yes = vip_counts.get('Yes', 0)
            st.metric("VIP User Incidents", vip_yes,
                     delta=f"{vip_yes/len(data_df)*100:.2f}% of total")
        
        with col2:
            vip_no = vip_counts.get('No', 0)
            st.metric("Non-VIP User Incidents", vip_no,
                     delta=f"{vip_no/len(data_df)*100:.2f}% of total")

    st.markdown("---")

    # Performance Summary
    st.markdown("### ⏱️ Response Time Analysis")
    
    # Generate and display summary directly
    response_summary = generate_data_summary_with_ollama(
        "Response Time Analysis", 
        summary_data.get("Response Time Analysis", {})
    )
    st.info(response_summary)

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
