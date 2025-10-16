import requests
import json
import streamlit as st
from typing import Dict, Any
import pandas as pd
import hashlib

def convert_to_json_serializable(obj):
    """Convert numpy/pandas types to native Python types"""
    import numpy as np
    if isinstance(obj, dict):
        return {k: convert_to_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_json_serializable(item) for item in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif pd.isna(obj):
        return None
    return obj


def _create_cache_key(section_name: str, data: Dict[str, Any]) -> str:
    """Create a unique cache key for the summary"""
    data_str = json.dumps(convert_to_json_serializable(data), sort_keys=True)
    hash_obj = hashlib.md5(f"{section_name}_{data_str}".encode())
    return f"summary_cache_{hash_obj.hexdigest()}"


@st.cache_data(ttl=3600, show_spinner=False)  # Cache for 1 hour
def generate_data_summary_with_ollama(section_name: str, data: Dict[str, Any]) -> str:
    """
    Generate a 2-3 line summary for a metric section using actual data
    CACHED to prevent regeneration on every rerun
    
    Args:
        section_name: Name of the section
        data: Dictionary containing the relevant metrics/data for this section
    
    Returns:
        Generated summary string with insights from the data
    """
    
    # Create contextual prompt
    prompt = create_contextual_prompt(section_name, data)
    
    try:
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': 'qwen2.5:0.5b',
                'prompt': prompt,
                'stream': False
            },
            timeout=300
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', '').strip()
        else:
            return generate_fallback_summary(section_name, data)
            
    except Exception as e:
        print(f"Error generating summary for {section_name}: {e}")
        return generate_fallback_summary(section_name, data)


def format_number(value, decimals=2):
    """Format number with specified decimal places"""
    if value == 'N/A' or value is None:
        return 'N/A'
    try:
        if isinstance(value, str):
            value = float(value)
        return f"{value:.{decimals}f}"
    except:
        return value


def create_contextual_prompt(section_name: str, data: Dict[str, Any]) -> str:
    """Create detailed prompts with actual data for each section"""
    
    if section_name == "Alert Classification":
        tp_pct = format_number(data.get('tp_percentage', 0))
        fp_pct = format_number(data.get('fp_percentage', 0))
        bp_pct = format_number(data.get('bp_percentage', 0))
        
        prompt = f"""Analyze this alert classification data and write a 2-3 line professional summary for a SOC dashboard:
    - True Positives: {data.get('true_positives', 0)} ({tp_pct}%)
    - False Positives: {data.get('false_positives', 0)} ({fp_pct}%)
    - Benign Positives: {data.get('benign_positives', 0)} ({bp_pct}%)

    Focus on: detection accuracy, alert quality implications, and actionable insights. Avoid repeating the numbers unnecessarily."""

    elif section_name == "VIP User Distribution":
        prompt = f"""Analyze this VIP user distribution data and write a 2-3 line summary:
    - VIP User Incidents: {data.get('vip_count', 0)} ({format_number(data.get('vip_percentage', 0))}%)
    - Non-VIP Incidents: {data.get('non_vip_count', 0)} ({format_number(data.get('non_vip_percentage', 0))}%)
    - VIP Avg MTTR: {data.get('vip_avg_mttr', 'N/A')} minutes
    - Non-VIP Avg MTTR: {data.get('non_vip_avg_mttr', 'N/A')} minutes

    Highlight resource prioritization and response time differences."""

    elif section_name == "Response Time Analysis":
        mttr_mean = format_number(data.get('mttr_mean'))
        mttr_median = format_number(data.get('mttr_median'))
        mttr_90th = format_number(data.get('mttr_90th'))
        mttd_mean = format_number(data.get('mttd_mean'))
        mttd_median = format_number(data.get('mttd_median'))
        
        prompt = f"""Analyze this SOC team's response metrics and write a 2-3 line executive summary:
    MTTR (Resolution): Mean {mttr_mean} min, Median {mttr_median} min, 90th percentile {mttr_90th} min
    - {data.get('mttr_fast', 0)} incidents resolved in ≤15 minutes
    MTTD (Detection): Mean {mttd_mean} min, Median {mttd_median} min
    - {data.get('mttd_fast', 0)} incidents detected in ≤5 minutes

    Assess team efficiency, highlight strengths, and note if response times meet industry benchmarks (MTTR <30 min ideal, MTTD <10 min excellent)."""

    elif section_name == "Daily Incident Timeline":
        avg_per_day = format_number(data.get('avg_per_day', 0))
        
        prompt = f"""Based on this incident timeline data, write a 2-3 line summary:
- Date Range: {data.get('date_start', 'N/A')} to {data.get('date_end', 'N/A')}
- Total Days: {data.get('duration_days', 0)}
- Average Incidents per Day: {avg_per_day}
- Busiest Day: {data.get('busiest_day', 'N/A')} with {data.get('max_incidents', 0)} incidents
- Quietest Day: {data.get('quietest_day', 'N/A')} with {data.get('min_incidents', 0)} incidents

Identify trends and patterns in incident occurrence."""

    elif section_name == "Incident Pattern Heatmap":
        prompt = f"""Based on this incident pattern data, write a 2-3 line summary:
- Busiest Day of Week: {data.get('busiest_day_of_week', 'N/A')} with {data.get('busiest_day_count', 0)} incidents
- Quietest Day of Week: {data.get('quietest_day_of_week', 'N/A')} with {data.get('quietest_day_count', 0)} incidents
- Peak Hour: {data.get('peak_hour', 'N/A')}:00 with {data.get('peak_hour_count', 0)} incidents
- Quietest Hour: {data.get('quiet_hour', 'N/A')}:00 with {data.get('quiet_hour_count', 0)} incidents

Identify temporal patterns for resource planning."""

    else:
        prompt = f"""Based on this data: {json.dumps(convert_to_json_serializable(data), indent=2)}
Write a 2-3 line professional summary analyzing the key insights."""

    return prompt


def generate_fallback_summary(section_name: str, data: Dict[str, Any]) -> str:
    """Generate fallback summary when LLM is unavailable"""
    
    if section_name == "Alert Classification":
        tp_pct = format_number(data.get('tp_percentage', 0))
        fp_pct = format_number(data.get('fp_percentage', 0))
        bp_pct = format_number(data.get('bp_percentage', 0))
        return f"Out of total alerts, {tp_pct}% were true positives, {fp_pct}% were false positives, and {bp_pct}% were benign. This distribution helps assess detection accuracy and tune alerting mechanisms."

    elif section_name == "VIP User Distribution":
        vip_pct = format_number(data.get('vip_percentage', 0))
        return f"VIP users account for {vip_pct}% of incidents. VIP incidents average {data.get('vip_avg_mttr', 'N/A')} min resolution time vs {data.get('non_vip_avg_mttr', 'N/A')} min for non-VIP, indicating prioritization effectiveness."

    elif section_name == "Response Time Analysis":
        mttr_mean = format_number(data.get('mttr_mean'))
        mttr_median = format_number(data.get('mttr_median'))
        mttd_mean = format_number(data.get('mttd_mean'))
        return f"Team achieved an average resolution time of {mttr_mean} minutes (median: {mttr_median} min) and detection time of {mttd_mean} minutes. {data.get('mttr_fast', 0)} incidents were resolved in under 15 minutes, showing efficient response capabilities."

    elif section_name == "Daily Incident Timeline":
        avg_per_day = format_number(data.get('avg_per_day', 0))
        return f"Over {data.get('duration_days', 0)} days, incidents averaged {avg_per_day} per day, with the busiest day ({data.get('busiest_day', 'N/A')}) seeing {data.get('max_incidents', 0)} incidents. This trend helps identify workload patterns and resource needs."

    elif section_name == "Incident Pattern Heatmap":
        return f"{data.get('busiest_day_of_week', 'N/A')} is the busiest day with {data.get('busiest_day_count', 0)} incidents, and peak activity occurs at {data.get('peak_hour', 'N/A')}:00 hours. These patterns guide optimal staffing and resource allocation."

    return f"Analysis summary for {section_name} based on provided metrics."


def extract_summary_data(metrics: Dict, data_df) -> Dict[str, Dict]:
    """Extract relevant data for each section from metrics"""
    
    summary_data = {}
    
    # Alert Classification Data
    if 'classification_analysis' in metrics:
        ca = metrics['classification_analysis']
        tp = ca.get('true_positives', 0)
        fp = ca.get('false_positives', 0)
        bp = ca.get('benign_positives', 0)
        
        summary_data["Alert Classification"] = {
            'true_positives': tp,
            'false_positives': fp,
            'benign_positives': bp,
            'tp_percentage': ca.get('tp_rate', 0),
            'fp_percentage': ca.get('fp_rate', 0),
            'bp_percentage': ca.get('bp_rate', 0)
        }
    
    # Response Time Data
    summary_data["Response Time Analysis"] = {
        'mttr_mean': metrics.get('mttr_analysis', {}).get('mean', 'N/A'),
        'mttr_median': metrics.get('mttr_analysis', {}).get('median', 'N/A'),
        'mttr_90th': metrics.get('mttr_analysis', {}).get('percentiles', {}).get('90th', 'N/A'),
        'mttr_fast': metrics.get('mttr_analysis', {}).get('under_15_min', 0),
        'mttd_mean': metrics.get('mttd_analysis', {}).get('mean', 'N/A'),
        'mttd_median': metrics.get('mttd_analysis', {}).get('median', 'N/A'),
        'mttd_fast': metrics.get('mttd_analysis', {}).get('fast_detection', 0)
    }
    
    # VIP User Data
    if 'vip_analysis' in metrics:
        va = metrics['vip_analysis']
        vip_mttr = va.get('vip_avg_mttr')
        non_vip_mttr = va.get('non_vip_avg_mttr')
        
        summary_data["VIP User Distribution"] = {
            'vip_count': va.get('vip_users', 0),
            'non_vip_count': va.get('non_vip_users', 0),
            'vip_percentage': va.get('vip_percentage', 0),
            'non_vip_percentage': va.get('non_vip_percentage', 0),
            'vip_avg_mttr': f"{vip_mttr:.1f}" if vip_mttr is not None else 'N/A',
            'non_vip_avg_mttr': f"{non_vip_mttr:.1f}" if non_vip_mttr is not None else 'N/A'
        }
    
    # Timeline Data
    if 'date_range' in metrics and 'daily_patterns' in metrics:
        dr = metrics['date_range']
        dp = metrics['daily_patterns']
        summary_data["Daily Incident Timeline"] = {
            'date_start': str(dr.get('start', 'N/A')),
            'date_end': str(dr.get('end', 'N/A')),
            'duration_days': dr.get('duration_days', 0),
            'avg_per_day': dp.get('avg_incidents_per_day', 0),
            'busiest_day': dp.get('busiest_day', 'N/A'),
            'max_incidents': dp.get('max_incidents_day', 0),
            'quietest_day': dp.get('quietest_day', 'N/A'),
            'min_incidents': dp.get('min_incidents_day', 0)
        }
    
    # MTTR Distribution Data
    if 'mttr_analysis' in metrics:
        ma = metrics['mttr_analysis']
        excellent = ma.get('under_15_min', 0)
        over_30 = ma.get('over_30_min', 0)
        over_60 = ma.get('over_60_min', 0)
        
        good_count = over_30 - over_60
        moderate_count = over_30 - over_60
        
        summary_data["Resolution Time Distribution"] = {
            'excellent_count': excellent,
            'good_count': good_count if good_count > 0 else 0,
            'moderate_count': moderate_count if moderate_count > 0 else 0,
            'critical_count': over_60,
            'mean_mttr': f"{ma.get('mean', 0):.1f}",
            'median_mttr': f"{ma.get('median', 0):.1f}"
        }
    
    # Heatmap Pattern Data
    if 'weekly_patterns' in metrics:
        wp = metrics['weekly_patterns']
        busiest = max(wp.items(), key=lambda x: x[1])
        quietest = min(wp.items(), key=lambda x: x[1])
        
        summary_data["Incident Pattern Heatmap"] = {
            'busiest_day_of_week': busiest[0],
            'busiest_day_count': busiest[1],
            'quietest_day_of_week': quietest[0],
            'quietest_day_count': quietest[1],
            'peak_hour': 'N/A',
            'peak_hour_count': 0,
            'quiet_hour': 'N/A',
            'quiet_hour_count': 0
        }
    
    return summary_data