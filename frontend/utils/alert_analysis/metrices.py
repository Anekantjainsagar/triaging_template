import re
import pandas as pd
import numpy as np
from typing import Dict


def safe_to_numeric(series, column_name="column"):
    """
    Safely convert series to numeric, handling string values and errors

    Args:
        series: Pandas series to convert
        column_name: Name of column for logging

    Returns:
        Numeric series with NaN for unconvertible values
    """
    try:
        # Convert to numeric, coercing errors to NaN
        numeric_series = pd.to_numeric(series, errors="coerce")

        # Log warning if many values were converted to NaN
        na_count = numeric_series.isna().sum()
        original_na = series.isna().sum()

        if na_count > original_na:
            print(
                f"Warning: {na_count - original_na} non-numeric values in '{column_name}' converted to NaN"
            )

        return numeric_series
    except Exception as e:
        print(f"Error converting '{column_name}' to numeric: {e}")
        return pd.Series([np.nan] * len(series))


def get_column_name(data_df, possible_names):
    """
    Find column name from list of possibilities (handles API vs original names)

    Args:
        data_df: DataFrame to search
        possible_names: List of possible column names

    Returns:
        First matching column name or None
    """
    for name in possible_names:
        if name in data_df.columns:
            return name
    return None


def extract_detailed_metrics(data_df: pd.DataFrame) -> Dict:
    """Extract comprehensive metrics from the incident data"""
    metrics = {}

    # Basic incident statistics
    metrics["total_incidents"] = len(data_df)

    # Handle RULE column (could be 'RULE' or 'rule')
    rule_col = get_column_name(data_df, ["RULE", "rule"])
    metrics["unique_rules"] = data_df[rule_col].nunique() if rule_col else 0

    # Time-based analysis
    date_col = get_column_name(data_df, ["Date", "date", "reported_time_stamp"])
    if date_col:
        data_df[date_col] = pd.to_datetime(data_df[date_col], errors="coerce")
        metrics["date_range"] = {
            "start": data_df[date_col].min(),
            "end": data_df[date_col].max(),
            "duration_days": (data_df[date_col].max() - data_df[date_col].min()).days,
            "unique_dates": data_df[date_col].dt.date.nunique(),
        }

        # Daily incident patterns
        daily_incidents = data_df.groupby(data_df[date_col].dt.date).size()
        metrics["daily_patterns"] = {
            "avg_incidents_per_day": daily_incidents.mean(),
            "max_incidents_day": daily_incidents.max(),
            "min_incidents_day": daily_incidents.min(),
            "busiest_day": str(daily_incidents.idxmax()),
            "quietest_day": str(daily_incidents.idxmin()),
        }

        # Weekly patterns
        dow_col = get_column_name(data_df, ["DayOfWeek", "day_of_week"])
        if dow_col:
            weekday_names = [
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
                "Sunday",
            ]
            weekly_pattern = data_df[dow_col].value_counts().sort_index()
            metrics["weekly_patterns"] = {
                weekday_names[i]: weekly_pattern.get(i, 0) for i in range(7)
            }

    # Performance metrics (MTTR) - Handle both formats
    mttr_col = get_column_name(data_df, ["MTTR    (Mins)", "mttr_mins", "MTTR (Mins)"])
    if mttr_col:
        # Convert to numeric, handling strings
        mttr_data = safe_to_numeric(data_df[mttr_col], mttr_col).dropna()

        if len(mttr_data) > 0:
            metrics["mttr_analysis"] = {
                "mean": float(mttr_data.mean()),
                "median": float(mttr_data.median()),
                "std": float(mttr_data.std()),
                "min": float(mttr_data.min()),
                "max": float(mttr_data.max()),
                "percentiles": {
                    "25th": float(mttr_data.quantile(0.25)),
                    "50th": float(mttr_data.quantile(0.50)),
                    "75th": float(mttr_data.quantile(0.75)),
                    "90th": float(mttr_data.quantile(0.90)),
                    "95th": float(mttr_data.quantile(0.95)),
                },
                "over_30_min": int((mttr_data > 30).sum()),
                "over_60_min": int((mttr_data > 60).sum()),
                "under_15_min": int((mttr_data <= 15).sum()),
            }

    # Performance metrics (MTTD) - Handle both formats
    mttd_col = get_column_name(data_df, ["MTTD (Mins)", "mttd_mins", "MTTD    (Mins)"])
    if mttd_col:
        # Convert to numeric, handling strings
        mttd_data = safe_to_numeric(data_df[mttd_col], mttd_col).dropna()

        if len(mttd_data) > 0:
            metrics["mttd_analysis"] = {
                "mean": float(mttd_data.mean()),
                "median": float(mttd_data.median()),
                "std": float(mttd_data.std()),
                "min": float(mttd_data.min()),
                "max": float(mttd_data.max()),
                "immediate_detection": int((mttd_data <= 1).sum()),
                "fast_detection": int((mttd_data <= 5).sum()),
                "slow_detection": int((mttd_data > 15).sum()),
            }

    # Engineer performance analysis
    engineer_col = get_column_name(
        data_df, ["Name of the Shift Engineer", "shift_engineer"]
    )
    if engineer_col:
        # Determine which column to use for counting
        count_col = "incident_no" if "incident_no" in data_df.columns else engineer_col
        agg_dict = {count_col: "count"}

        # Build aggregation dynamically based on available columns
        if mttr_col:
            agg_dict[mttr_col] = ["mean", "median", "std"]
        if mttd_col:
            agg_dict[mttd_col] = ["mean", "median"]

        priority_col = get_column_name(data_df, ["Priority", "priority"])
        if priority_col:
            agg_dict[priority_col] = lambda x: (
                x.mode().iloc[0] if len(x.mode()) > 0 else "Unknown"
            )

        try:
            engineer_stats = data_df.groupby(engineer_col).agg(agg_dict).round(2)

            # Flatten column names
            engineer_stats.columns = [
                f"{col[0]}_{col[1]}" if isinstance(col, tuple) else col
                for col in engineer_stats.columns
            ]

            metrics["engineer_performance"] = {
                "total_engineers": len(engineer_stats),
                "performance_summary": engineer_stats.to_dict("index"),
            }
        except Exception as e:
            print(f"Warning: Could not generate engineer performance metrics: {e}")

    # Priority and classification analysis
    priority_col = get_column_name(data_df, ["Priority", "priority"])
    if priority_col:
        priority_dist = data_df[priority_col].value_counts()
        metrics["priority_analysis"] = {
            "distribution": priority_dist.to_dict(),
            "percentages": (priority_dist / len(data_df) * 100).round(2).to_dict(),
            "most_common": (
                priority_dist.index[0] if len(priority_dist) > 0 else "Unknown"
            ),
        }

        if mttr_col:
            metrics["priority_analysis"]["priority_vs_mttr"] = (
                data_df.groupby(priority_col)[mttr_col]
                .apply(lambda x: safe_to_numeric(x).mean())
                .to_dict()
            )

    # False positive analysis
    fp_col = get_column_name(
        data_df, ["False / True Positive", "classification", "alert_classification"]
    )
    if fp_col:
        fp_column = data_df[fp_col].astype(str).str.lower().str.strip()

        # Standardize values
        fp_standardized = fp_column.replace(
            {
                "truepositive": "true positive",
                "falsepositive": "false positive",
                "benignpositive": "benign positive",
            }
        )

        total_classified = len(fp_standardized.dropna())
        true_positives = fp_standardized.str.contains("true positive", na=False).sum()
        false_positives = fp_standardized.str.contains("false positive", na=False).sum()
        benign_positives = fp_standardized.str.contains(
            "benign positive", na=False
        ).sum()

        metrics["classification_analysis"] = {
            "total_classified": int(total_classified),
            "true_positives": int(true_positives),
            "false_positives": int(false_positives),
            "benign_positives": int(benign_positives),
            "tp_rate": float(
                (true_positives / total_classified * 100) if total_classified > 0 else 0
            ),
            "fp_rate": float(
                (false_positives / total_classified * 100)
                if total_classified > 0
                else 0
            ),
            "bp_rate": float(
                (benign_positives / total_classified * 100)
                if total_classified > 0
                else 0
            ),
        }

    # VIP User analysis
    vip_col = get_column_name(
        data_df, ["VIP Users ", "VIP Users", "vip_users", "is_vip"]
    )
    if vip_col:
        vip_column = data_df[vip_col].astype(str).str.strip().str.lower()
        vip_standardized = vip_column.replace(
            {"yes": "Yes", "no": "No", "y": "Yes", "n": "No"}
        )

        total_vip = len(vip_standardized.dropna())
        vip_yes = (vip_standardized == "Yes").sum()
        vip_no = (vip_standardized == "No").sum()

        # Calculate average MTTR for VIP vs Non-VIP users
        vip_mttr_avg = None
        non_vip_mttr_avg = None

        if mttr_col:
            data_df_temp = data_df.copy()
            data_df_temp["VIP_Standardized"] = vip_standardized

            vip_mttr = safe_to_numeric(
                data_df_temp[data_df_temp["VIP_Standardized"] == "Yes"][mttr_col]
            ).dropna()
            non_vip_mttr = safe_to_numeric(
                data_df_temp[data_df_temp["VIP_Standardized"] == "No"][mttr_col]
            ).dropna()

            vip_mttr_avg = float(vip_mttr.mean()) if len(vip_mttr) > 0 else None
            non_vip_mttr_avg = (
                float(non_vip_mttr.mean()) if len(non_vip_mttr) > 0 else None
            )

        metrics["vip_analysis"] = {
            "total_with_vip_data": int(total_vip),
            "vip_users": int(vip_yes),
            "non_vip_users": int(vip_no),
            "vip_percentage": float(
                (vip_yes / total_vip * 100) if total_vip > 0 else 0
            ),
            "non_vip_percentage": float(
                (vip_no / total_vip * 100) if total_vip > 0 else 0
            ),
            "vip_avg_mttr": vip_mttr_avg,
            "non_vip_avg_mttr": non_vip_mttr_avg,
        }

    # Shift analysis
    shift_col = get_column_name(data_df, ["SHIFT", "shift"])
    if shift_col:
        agg_dict = {}
        count_col = get_column_name(data_df, ["S.NO.", "incident_no", "id"])
        if count_col:
            agg_dict[count_col] = "count"
        if mttr_col:
            agg_dict[mttr_col] = lambda x: safe_to_numeric(x).mean()
        if priority_col:
            agg_dict[priority_col] = lambda x: x.value_counts().to_dict()

        if agg_dict:
            shift_analysis = data_df.groupby(shift_col).agg(agg_dict)

            metrics["shift_analysis"] = {
                "distribution": (
                    shift_analysis.iloc[:, 0].to_dict()
                    if len(shift_analysis.columns) > 0
                    else {}
                ),
                "performance": (
                    shift_analysis.iloc[:, 1].to_dict()
                    if len(shift_analysis.columns) > 1
                    else {}
                ),
            }

    # Quality and compliance analysis
    quality_col = get_column_name(data_df, ["Quality Audit", "quality_audit"])
    if quality_col:
        quality_dist = data_df[quality_col].value_counts()
        metrics["quality_analysis"] = {
            "distribution": quality_dist.to_dict(),
            "pass_rate": float(
                (quality_dist.get("Pass", 0) / len(data_df) * 100)
                if len(data_df) > 0
                else 0
            ),
            "fail_rate": float(
                (quality_dist.get("Fail", 0) / len(data_df) * 100)
                if len(data_df) > 0
                else 0
            ),
        }

    # SLA analysis
    sla_col = get_column_name(data_df, ["Time To Breach SLA", "sla_time"])
    if sla_col:
        sla_data = safe_to_numeric(data_df[sla_col]).dropna()
        if len(sla_data) > 0:
            breaches = (sla_data < 0).sum()
            metrics["sla_analysis"] = {
                "total_with_sla_data": int(len(sla_data)),
                "breaches": int(breaches),
                "breach_rate": float(breaches / len(sla_data) * 100),
                "avg_remaining_time": float(sla_data.mean()),
                "critical_sla_incidents": int(len(sla_data[sla_data < 60])),
            }

    # Incident description analysis
    desc_col = get_column_name(data_df, ["Short Incident Description", "description"])
    if desc_col:
        descriptions = data_df[desc_col].dropna()
        metrics["description_analysis"] = {
            "total_with_descriptions": int(len(descriptions)),
            "avg_description_length": float(
                descriptions.str.len().mean() if len(descriptions) > 0 else 0
            ),
            "common_keywords": (
                extract_common_keywords(descriptions) if len(descriptions) > 0 else {}
            ),
        }

    return metrics


def extract_common_keywords(descriptions):
    """Extract common keywords from incident descriptions"""
    all_text = " ".join(descriptions.astype(str).str.lower())
    words = re.findall(r"\b\w{4,}\b", all_text)
    word_counts = pd.Series(words).value_counts()
    return word_counts.head(10).to_dict()
