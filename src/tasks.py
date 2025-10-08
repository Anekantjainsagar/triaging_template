import os
from crewai import Task
import json
from textwrap import dedent


class TriagingTasks:
    def __init__(self):
        pass

    def real_time_prediction_task(
        self,
        agent,
        triaging_comments: dict,
        rule_number: str,
        rule_history: dict,
        template_content: str,
    ):
        """
        FIXED: Prediction based on template's decision criteria.
        """
        all_comments = "\n\n".join(
            [f"**{step}**: {comment}" for step, comment in triaging_comments.items()]
        )

        return Task(
            description=dedent(
                f"""
                Predict classification for {rule_number} based on completed triaging.
                
                ===========================================================================
                COMPLETED INVESTIGATION FINDINGS:
                ===========================================================================
                {all_comments}
                
                ===========================================================================
                TEMPLATE'S DECISION CRITERIA (MUST FOLLOW):
                ===========================================================================
                {template_content}
                
                Extract from template:
                - What conditions = True Positive?
                - What conditions = False Positive?
                - What are escalation triggers?
                
                ===========================================================================
                HISTORICAL BASELINE:
                ===========================================================================
                - Total Past Incidents: {rule_history.get('total_incidents', 0)}
                - FP Rate: {rule_history.get('fp_rate', 0)}%
                - TP Rate: {rule_history.get('tp_rate', 0)}%
                - Common FP Indicators: {rule_history.get('fp_indicators', 'N/A')}
                - Common TP Indicators: {rule_history.get('tp_indicators', 'N/A')}
                
                ===========================================================================
                PREDICTION PROCESS (FOLLOW EXACTLY):
                ===========================================================================
                
                **STEP 1: Map findings to template decision criteria**
                
                Go through each completed step's findings:
                - Does finding match template's FP criteria? (e.g., "clean IP", "user confirmed")
                - Does finding match template's TP criteria? (e.g., "malicious IP", "user denied")
                - Were any escalation triggers met?
                
                **STEP 2: Calculate probability adjustments**
                
                Start with historical baseline: FP={rule_history.get('fp_rate', 50)}%, TP={rule_history.get('tp_rate', 50)}%
                
                For EACH finding, adjust:
                - Strong FP indicator (matches template FP criteria) → +15-20% FP
                - Weak FP indicator → +5-10% FP
                - Strong TP indicator (matches template TP criteria) → +15-20% TP
                - Weak TP indicator → +5-10% TP
                
                **STEP 3: Normalize to 100%**
                
                Ensure: FP% + TP% + BP% = 100%
                
                **STEP 4: Validate against template**
                
                Does highest percentage match template's decision logic?
                - If template says "if clean IP + user confirm → FP", and both found → FP% should be highest
                
                ===========================================================================
                OUTPUT FORMAT (MANDATORY):
                ===========================================================================
                
                ---
                PREDICTION_TYPE: [False Positive / True Positive / Benign Positive]
                
                CONFIDENCE_PERCENTAGES:
                - False Positive Likelihood: [X]%
                - True Positive Likelihood: [Y]%
                - Benign Positive Likelihood: [Z]%
                (MUST SUM TO 100%)
                
                CONFIDENCE_LEVEL: [High / Medium / Low]
                
                KEY_FACTORS:
                1. [Step N finding]: [How it matches template criteria]
                2. [Step M finding]: [How it matches template criteria]
                3. [Template decision point met/not met]
                4. [Historical pattern alignment]
                
                TEMPLATE_ALIGNMENT:
                "[Explain how findings match template's decision logic]"
                Example: "Template states: 'If clean IP AND MFA success → FP'. Both conditions met in Steps 2 and 4."
                
                HISTORICAL_COMPARISON:
                "[Compare to past {rule_history.get('total_incidents', 0)} incidents]"
                Example: "Findings match 82% of past FP cases where clean IP and user confirmation were found."
                
                REASONING:
                "[2-3 sentences why these percentages]"
                
                RECOMMENDED_ACTION:
                "[From template's escalation logic]"
                - If TP → [action from template]
                - If FP → Close with justification
                ---
                
                ===========================================================================
                EXAMPLE OUTPUT:
                ===========================================================================
                
                ---
                PREDICTION_TYPE: False Positive
                
                CONFIDENCE_PERCENTAGES:
                - False Positive Likelihood: 85%
                - True Positive Likelihood: 10%
                - Benign Positive Likelihood: 5%
                
                CONFIDENCE_LEVEL: High
                
                KEY_FACTORS:
                1. Step 2 (IP Check): Found "Clean IP, No threats" - matches template FP criteria
                2. Step 4 (User Verification): User confirmed legitimate travel - strong FP indicator per template
                3. Step 3 (Device Check): Known device with MFA satisfied - template FP pattern
                4. Historical: 78% of past incidents with these patterns were FP
                
                TEMPLATE_ALIGNMENT:
                Template decision logic states: "If clean IP AND user confirms travel AND known device → False Positive". All three conditions were met across Steps 2, 3, and 4, strongly supporting FP classification per template guidance.
                
                HISTORICAL_COMPARISON:
                This incident matches 85% of the 58 past {rule_number} cases that were False Positives. Historical FP rate is 78%, and this case shows the same pattern: clean IP + user confirmation + known device + MFA satisfied.
                
                REASONING:
                The combination of clean IP reputation (Step 2), user confirmation of legitimate travel (Step 4), and known device with MFA (Step 3) strongly indicates legitimate activity. These findings align perfectly with the template's FP decision criteria and match 85% of historical FP patterns.
                
                RECOMMENDED_ACTION:
                Per template: Close as False Positive. Document: "Legitimate user travel confirmed via IP reputation check, user verification, and device recognition. No escalation required."
                ---
                
                ===========================================================================
                VALIDATION CHECKLIST:
                ===========================================================================
                
                Before outputting, verify:
                ✅ Percentages total 100%
                ✅ Prediction type matches highest %
                ✅ Key factors reference actual step findings
                ✅ Template alignment explains decision logic match
                ✅ Historical comparison included
                ✅ Recommended action from template
            """
            ),
            expected_output=dedent(
                """
                Complete prediction with:
                1. Prediction type (FP/TP/BP)
                2. Three percentages summing to 100%
                3. Confidence level
                4. 4-5 key factors referencing steps
                5. Template alignment explanation
                6. Historical comparison
                7. Clear reasoning (2-3 sentences)
                8. Recommended action from template
                
                Must match MANDATORY OUTPUT FORMAT exactly.
            """
            ),
            agent=agent,
        )

    def predict_outcome_task(self, agent, consolidated_data, rule_number):
        """Task to predict incident outcomes based on historical data."""
        return Task(
            description=dedent(
                f"""
                Predict the outcome for: {rule_number}
                
                Perform a comprehensive analysis of this incident: {str(consolidated_data)}...
                
                INCIDENT DATA:
                {json.dumps(consolidated_data, indent=2)}
                
                ANALYSIS STEPS:
                1. Extract and analyze resolver comments for key indicators
                2. Review historical classification and justification
                3. Apply pattern recognition based on known TP/FP patterns
                4. Consider context: priority, VIP users, time of day, etc.
                
                Historical context:
                - Previous Classification: {consolidated_data.get('false_true_positive', 'N/A')}
                - Justification: {consolidated_data.get('why_false_positive', 'N/A')}
                - Resolver Comments: {consolidated_data.get('resolver_comments', 'N/A')}
                
                FALSE POSITIVE indicators:
                - IP reputation explicitly marked as "clean"
                - "Known device" or "registered device" mentioned
                - "Known apps" or "legitimate applications"
                - "MFA satisfied" or "MFA enabled and successful"
                - "Legitimate user behavior"
                - VPN usage (Nord VPN, ExpressVPN, corporate VPN)
                - "BAS testing" or "security testing"
                - "Nothing suspicious found"
                - "No unauthorized access"
                - User confirmation of legitimate activity
                
                TRUE POSITIVE indicators:
                - "Services not running" or "service down"
                - "Unauthorized access" or "suspicious access"
                - "Malicious IP" or "bad reputation"
                - "Suspicious activity detected"
                - "Unknown device" or "unregistered device"
                - "Failed MFA" or "MFA bypass"
                - "Escalated to L3/SOC"
                - "Anomalous behavior"
                - "Data exfiltration" or "unusual downloads"
                - Multiple failed login attempts
                - Access to sensitive resources
                
                UNCERTAIN indicators:
                - Incomplete investigation
                - Missing data points
                - Conflicting information
                - Pending user confirmation
                
                Historical context:
                - Previous Classification: {consolidated_data.get('false_true_positive', 'N/A')}
                - Justification: {consolidated_data.get('why_false_positive', 'N/A')}
                - Resolver Comments: {consolidated_data.get('resolver_comments', 'N/A')}
                
                Provide prediction with:
                - Classification (Likely True Positive / Likely False Positive / Requires Further Investigation)
                - Confidence Level (High 80-100% / Medium 50-79% / Low <50%)
                - Detailed reasoning with specific evidence
                - Key indicators that led to this prediction
            """
            ),
            expected_output=dedent(
                """
                A comprehensive prediction summary:
                
                PREDICTION: [Likely True Positive / Likely False Positive / Requires Further Investigation]
                
                CONFIDENCE: [High (80-100%) / Medium (50-79%) / Low (<50%)]
                
                REASONING: [3-5 sentences explaining the prediction based on specific evidence from the incident data. Reference exact phrases or indicators found in resolver comments, IP status, device information, etc.]
                
                KEY_INDICATORS: [Bullet list of 3-5 specific data points that support this prediction]
                
                RECOMMENDATION: [Specific next steps based on prediction]
            """
            ),
            agent=agent,
        )

