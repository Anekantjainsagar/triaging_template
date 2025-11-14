"""
Enhanced configuration for improved predictions and analysis
"""
import os
from typing import Dict, List, Any


class EnhancedAnalysisConfig:
    """Configuration for enhanced analysis features"""
    
    # UI Configuration
    UI_CONFIG = {
        "accordion_default_state": False,  # Closed by default as requested
        "show_progress_metrics": True,
        "enhanced_styling": True,
        "show_mitre_matrix_always": True,  # Always show MITRE matrix even if empty
        "max_findings_display": 10,
        "enable_real_time_updates": True
    }
    
    # Analysis Configuration
    ANALYSIS_CONFIG = {
        "min_confidence_threshold": 60,
        "max_parallel_workers": 4,
        "cache_results": True,
        "enhanced_error_handling": True,
        "detailed_logging": True,
        "specific_investigation_mode": True  # Enable more specific investigations
    }
    
    # MITRE ATT&CK Configuration
    MITRE_CONFIG = {
        "always_show_matrix": True,
        "include_sub_techniques": True,
        "show_predicted_steps": True,
        "enhanced_technique_mapping": True,
        "confidence_based_coloring": True,
        "include_procedures": True
    }
    
    # Investigation Specificity Improvements
    INVESTIGATION_IMPROVEMENTS = {
        "geographic_analysis": {
            "high_risk_countries": ["Russia", "China", "North Korea", "Iran", "Syria"],
            "impossible_travel_threshold_hours": 1,
            "suspicious_travel_threshold_hours": 3,
            "enable_geolocation_enrichment": True
        },
        "authentication_analysis": {
            "brute_force_threshold": 5,
            "credential_stuffing_indicators": ["multiple_ips", "rapid_attempts"],
            "mfa_bypass_detection": True,
            "session_anomaly_detection": True
        },
        "device_analysis": {
            "compliance_requirements": ["managed", "encrypted", "updated"],
            "trust_level_mapping": True,
            "device_fingerprinting": True
        },
        "privilege_analysis": {
            "admin_role_monitoring": True,
            "permission_change_tracking": True,
            "just_in_time_access_validation": True
        }
    }
    
    # Error Handling and Fallbacks
    ERROR_HANDLING = {
        "graceful_degradation": True,
        "fallback_to_basic_analysis": True,
        "retry_failed_requests": 3,
        "timeout_seconds": 30,
        "show_partial_results": True
    }
    
    # Data Quality Improvements
    DATA_QUALITY = {
        "validate_input_data": True,
        "sanitize_outputs": True,
        "handle_missing_fields": True,
        "normalize_timestamps": True,
        "standardize_formats": True
    }


class PredictionsEnhancementConfig:
    """Configuration for predictions tab enhancements"""
    
    @staticmethod
    def get_enhanced_finding_template() -> Dict[str, Any]:
        """Get template for enhanced findings with all required fields"""
        return {
            "category": "",
            "severity": "MEDIUM",
            "step_reference": "",
            "details": "",
            "evidence": "",
            "impact": "",
            "specific_indicators": [],
            "remediation_steps": [],
            "timeline_context": {
                "detection_time": "",
                "urgency": "Standard",
                "investigation_window": "72 hours"
            },
            "confidence_score": 70,
            "mitre_mapping": {
                "tactic": "",
                "technique": "",
                "technique_id": "",
                "sub_technique": "",
                "sub_technique_id": ""
            }
        }
    
    @staticmethod
    def get_severity_color_mapping() -> Dict[str, Dict[str, str]]:
        """Get color mapping for different severity levels"""
        return {
            "CRITICAL": {
                "bg": "#fee2e2",
                "border": "#dc2626", 
                "text": "#991b1b",
                "icon": "🔴"
            },
            "HIGH": {
                "bg": "#fed7aa",
                "border": "#f59e0b",
                "text": "#92400e", 
                "icon": "🟠"
            },
            "MEDIUM": {
                "bg": "#fef3c7",
                "border": "#f59e0b",
                "text": "#92400e",
                "icon": "🟡"
            },
            "LOW": {
                "bg": "#d1fae5",
                "border": "#10b981",
                "text": "#065f46",
                "icon": "🟢"
            }
        }
    
    @staticmethod
    def get_investigation_step_categories() -> List[str]:
        """Get standardized investigation step categories"""
        return [
            "Scope Verification",
            "User Account Analysis", 
            "IP Reputation Check",
            "Geographic Analysis",
            "Device/Endpoint Analysis",
            "Authentication Pattern Analysis",
            "Privilege Escalation Check",
            "Lateral Movement Detection",
            "Data Access Analysis",
            "Timeline Reconstruction"
        ]
    
    @staticmethod
    def get_mitre_tactic_descriptions() -> Dict[str, str]:
        """Get descriptions for MITRE ATT&CK tactics"""
        return {
            "Reconnaissance": "Gathering information about the target",
            "Resource Development": "Establishing resources for the attack",
            "Initial Access": "Gaining initial foothold in the network",
            "Execution": "Running malicious code on target systems",
            "Persistence": "Maintaining access to compromised systems",
            "Privilege Escalation": "Gaining higher-level permissions",
            "Defense Evasion": "Avoiding detection by security controls",
            "Credential Access": "Stealing account credentials",
            "Discovery": "Learning about the target environment",
            "Lateral Movement": "Moving through the network",
            "Collection": "Gathering data of interest",
            "Command and Control": "Communicating with compromised systems",
            "Exfiltration": "Stealing data from the network",
            "Impact": "Manipulating, interrupting, or destroying systems/data"
        }


class UIEnhancementConfig:
    """Configuration for UI enhancements"""
    
    @staticmethod
    def get_custom_css() -> str:
        """Get custom CSS for enhanced UI"""
        return """
        <style>
        .enhanced-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            border-radius: 15px;
            margin: 1rem 0;
            text-align: center;
        }
        
        .enhanced-header h1 {
            color: white;
            margin: 0;
            font-size: 2.5rem;
        }
        
        .enhanced-header p {
            color: rgba(255,255,255,0.9);
            margin: 0.5rem 0 0 0;
            font-size: 1.2rem;
        }
        
        .finding-card {
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-width: 2px;
            border-style: solid;
        }
        
        .finding-card h4 {
            margin: 0 0 1rem 0;
        }
        
        .finding-detail {
            background: white;
            padding: 0.8rem;
            border-radius: 5px;
            margin: 0.5rem 0;
        }
        
        .finding-detail strong {
            color: #374151;
        }
        
        .finding-detail span {
            color: #6b7280;
        }
        
        .metric-card {
            background: white;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
            border-width: 2px;
            border-style: solid;
        }
        
        .metric-card h3 {
            margin: 0 0 0.5rem 0;
        }
        
        .metric-card p {
            margin: 0;
            font-weight: bold;
            font-size: 1.1rem;
        }
        
        .progress-container {
            background: #f8fafc;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.875rem;
            font-weight: 600;
            margin: 0.25rem;
        }
        
        .status-badge.success {
            background: #d1fae5;
            color: #065f46;
        }
        
        .status-badge.warning {
            background: #fed7aa;
            color: #92400e;
        }
        
        .status-badge.error {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .accordion-header {
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .download-section {
            background: #f8fafc;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .download-section h3 {
            color: #374151;
            margin: 0 0 1rem 0;
        }
        </style>
        """
    
    @staticmethod
    def get_progress_html(current: int, total: int, status: str) -> str:
        """Get HTML for enhanced progress display"""
        percentage = (current / total * 100) if total > 0 else 0
        
        return f"""
        <div class="progress-container">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-weight: 600;">Analysis Progress</span>
                <span style="color: #6b7280;">{current}/{total} ({percentage:.1f}%)</span>
            </div>
            <div style="background: #e5e7eb; border-radius: 10px; height: 8px; overflow: hidden;">
                <div style="background: #667eea; height: 100%; width: {percentage}%; transition: width 0.3s ease;"></div>
            </div>
            <div style="margin-top: 0.5rem; color: #6b7280; font-size: 0.9rem;">
                {status}
            </div>
        </div>
        """


# Environment-specific configurations
def get_environment_config() -> Dict[str, Any]:
    """Get configuration based on environment"""
    
    testing_mode = os.getenv("TESTING", "false").lower() == "true"
    
    return {
        "testing_mode": testing_mode,
        "show_tabs": not testing_mode,  # Hide tabs in testing mode
        "enable_caching": not testing_mode,
        "detailed_logging": testing_mode,
        "mock_api_calls": testing_mode,
        "accordion_expanded_default": False,  # Always closed as requested
        "show_debug_info": testing_mode
    }


# Export main configurations
__all__ = [
    "EnhancedAnalysisConfig",
    "PredictionsEnhancementConfig", 
    "UIEnhancementConfig",
    "get_environment_config"
]