import re
import pandas as pd
from typing import Dict


def extract_detailed_metrics(data_df: pd.DataFrame) -> Dict:
    """Extract comprehensive metrics from the incident data"""
    metrics = {}

    # Basic incident statistics
    metrics["total_incidents"] = len(data_df)
    metrics["unique_rules"] = (
        data_df["RULE"].nunique() if "RULE" in data_df.columns else 0
    )

    # Time-based analysis
    if "Date" in data_df.columns:
        data_df["Date"] = pd.to_datetime(data_df["Date"], errors="coerce")
        metrics["date_range"] = {
            "start": data_df["Date"].min(),
            "end": data_df["Date"].max(),
            "duration_days": (data_df["Date"].max() - data_df["Date"].min()).days,
            "unique_dates": data_df["Date"].dt.date.nunique(),
        }

        # Daily incident patterns
        daily_incidents = data_df.groupby(data_df["Date"].dt.date).size()
        metrics["daily_patterns"] = {
            "avg_incidents_per_day": daily_incidents.mean(),
            "max_incidents_day": daily_incidents.max(),
            "min_incidents_day": daily_incidents.min(),
            "busiest_day": str(daily_incidents.idxmax()),
            "quietest_day": str(daily_incidents.idxmin()),
        }

        # Weekly patterns
        if "DayOfWeek" in data_df.columns:
            weekday_names = [
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
                "Sunday",
            ]
            weekly_pattern = data_df["DayOfWeek"].value_counts().sort_index()
            metrics["weekly_patterns"] = {
                weekday_names[i]: weekly_pattern.get(i, 0) for i in range(7)
            }

    # Performance metrics (MTTR/MTTD)
    if "MTTR    (Mins)" in data_df.columns:
        mttr_data = data_df["MTTR    (Mins)"].dropna()
        if len(mttr_data) > 0:
            metrics["mttr_analysis"] = {
                "mean": mttr_data.mean(),
                "median": mttr_data.median(),
                "std": mttr_data.std(),
                "min": mttr_data.min(),
                "max": mttr_data.max(),
                "percentiles": {
                    "25th": mttr_data.quantile(0.25),
                    "50th": mttr_data.quantile(0.50),
                    "75th": mttr_data.quantile(0.75),
                    "90th": mttr_data.quantile(0.90),
                    "95th": mttr_data.quantile(0.95),
                },
                "over_30_min": len(mttr_data[mttr_data > 30]),
                "over_60_min": len(mttr_data[mttr_data > 60]),
                "under_15_min": len(mttr_data[mttr_data <= 15]),
            }

    if "MTTD (Mins)" in data_df.columns:
        mttd_data = data_df["MTTD (Mins)"].dropna()
        if len(mttd_data) > 0:
            metrics["mttd_analysis"] = {
                "mean": mttd_data.mean(),
                "median": mttd_data.median(),
                "std": mttd_data.std(),
                "min": mttd_data.min(),
                "max": mttd_data.max(),
                "immediate_detection": len(mttd_data[mttd_data <= 1]),
                "fast_detection": len(mttd_data[mttd_data <= 5]),
                "slow_detection": len(mttd_data[mttd_data > 15]),
            }

    # Engineer performance analysis
    if "Name of the Shift Engineer" in data_df.columns:
        engineer_stats = (
            data_df.groupby("Name of the Shift Engineer")
            .agg(
                {
                    "S.NO.": "count",
                    "MTTR    (Mins)": ["mean", "median", "std"],
                    "MTTD (Mins)": ["mean", "median"],
                    "Priority": lambda x: (
                        x.mode().iloc[0] if len(x.mode()) > 0 else "Unknown"
                    ),
                }
            )
            .round(2)
        )

        # Flatten column names
        engineer_stats.columns = [
            "incident_count",
            "mttr_mean",
            "mttr_median",
            "mttr_std",
            "mttd_mean",
            "mttd_median",
            "common_priority",
        ]

        metrics["engineer_performance"] = {
            "total_engineers": len(engineer_stats),
            "most_active": engineer_stats["incident_count"].idxmax(),
            "best_mttr": engineer_stats["mttr_mean"].idxmin(),
            "worst_mttr": engineer_stats["mttr_mean"].idxmax(),
            "workload_distribution": engineer_stats["incident_count"].to_dict(),
            "performance_summary": engineer_stats.to_dict("index"),
        }

    # Priority and classification analysis
    if "Priority" in data_df.columns:
        priority_dist = data_df["Priority"].value_counts()
        metrics["priority_analysis"] = {
            "distribution": priority_dist.to_dict(),
            "percentages": (priority_dist / len(data_df) * 100).round(2).to_dict(),
            "most_common": priority_dist.index[0],
            "priority_vs_mttr": (
                data_df.groupby("Priority")["MTTR    (Mins)"].mean().to_dict()
                if "MTTR    (Mins)" in data_df.columns
                else {}
            ),
        }

    # False positive analysis
    if "False / True Positive" in data_df.columns:
        fp_column = data_df["False / True Positive"].astype(str).str.lower().str.strip()
        
        # Standardize values
        fp_standardized = fp_column.replace({
            'truepositive': 'true positive',
            'falsepositive': 'false positive',
            'benignpositive': 'benign positive',
        })
        
        total_classified = len(fp_standardized.dropna())
        true_positives = fp_standardized.str.contains("true positive", na=False).sum()
        false_positives = fp_standardized.str.contains("false positive", na=False).sum()
        benign_positives = fp_standardized.str.contains("benign positive", na=False).sum()
        
        metrics["classification_analysis"] = {
            "total_classified": total_classified,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "benign_positives": benign_positives,
            "tp_rate": (true_positives / total_classified * 100) if total_classified > 0 else 0,
            "fp_rate": (false_positives / total_classified * 100) if total_classified > 0 else 0,
            "bp_rate": (benign_positives / total_classified * 100) if total_classified > 0 else 0,
        }


    # VIP User analysis
    if "VIP Users " in data_df.columns:
        vip_column = data_df["VIP Users "].astype(str).str.strip().str.lower()
        vip_standardized = vip_column.replace({
            'yes': 'Yes',
            'no': 'No',
            'y': 'Yes',
            'n': 'No'
        })
        
        total_vip = len(vip_standardized.dropna())
        vip_yes = (vip_standardized == 'Yes').sum()
        vip_no = (vip_standardized == 'No').sum()
        
        # Calculate average MTTR for VIP vs Non-VIP users
        vip_mttr_avg = None
        non_vip_mttr_avg = None
        
        if "MTTR    (Mins)" in data_df.columns:
            data_df_temp = data_df.copy()
            data_df_temp['VIP_Standardized'] = vip_standardized
            
            vip_mttr = data_df_temp[data_df_temp['VIP_Standardized'] == 'Yes']['MTTR    (Mins)'].dropna()
            non_vip_mttr = data_df_temp[data_df_temp['VIP_Standardized'] == 'No']['MTTR    (Mins)'].dropna()
            
            vip_mttr_avg = vip_mttr.mean() if len(vip_mttr) > 0 else None
            non_vip_mttr_avg = non_vip_mttr.mean() if len(non_vip_mttr) > 0 else None
        
        metrics["vip_analysis"] = {
            "total_with_vip_data": total_vip,
            "vip_users": vip_yes,
            "non_vip_users": vip_no,
            "vip_percentage": (vip_yes / total_vip * 100) if total_vip > 0 else 0,
            "non_vip_percentage": (vip_no / total_vip * 100) if total_vip > 0 else 0,
            "vip_avg_mttr": vip_mttr_avg,
            "non_vip_avg_mttr": non_vip_mttr_avg,
        }

    # Shift analysis
    if "SHIFT" in data_df.columns:
        shift_analysis = data_df.groupby("SHIFT").agg(
            {
                "S.NO.": "count",
                "MTTR    (Mins)": "mean",
                "Priority": lambda x: x.value_counts().to_dict(),
            }
        )
        metrics["shift_analysis"] = {
            "distribution": shift_analysis["S.NO."].to_dict(),
            "performance": shift_analysis["MTTR    (Mins)"].to_dict(),
            "priority_patterns": shift_analysis["Priority"].to_dict(),
        }

    # Quality and compliance analysis
    if "Quality Audit" in data_df.columns:
        quality_dist = data_df["Quality Audit"].value_counts()
        metrics["quality_analysis"] = {
            "distribution": quality_dist.to_dict(),
            "pass_rate": (
                (quality_dist.get("Pass", 0) / len(data_df) * 100)
                if len(data_df) > 0
                else 0
            ),
            "fail_rate": (
                (quality_dist.get("Fail", 0) / len(data_df) * 100)
                if len(data_df) > 0
                else 0
            ),
        }

    # SLA analysis
    if "Time To Breach SLA" in data_df.columns:
        sla_data = data_df["Time To Breach SLA"].dropna()
        if len(sla_data) > 0:
            breaches = (sla_data < 0).sum()
            metrics["sla_analysis"] = {
                "total_with_sla_data": len(sla_data),
                "breaches": breaches,
                "breach_rate": (breaches / len(sla_data) * 100),
                "avg_remaining_time": sla_data.mean(),
                "critical_sla_incidents": len(
                    sla_data[sla_data < 60]
                ),  # Less than 1 hour remaining
            }

    # Incident description analysis
    if "Short Incident Description" in data_df.columns:
        descriptions = data_df["Short Incident Description"].dropna()
        metrics["description_analysis"] = {
            "total_with_descriptions": len(descriptions),
            "avg_description_length": (
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
    # Simple keyword extraction - can be enhanced
    words = re.findall(r"\b\w{4,}\b", all_text)  # Words with 4+ characters
    word_counts = pd.Series(words).value_counts()
    return word_counts.head(10).to_dict()