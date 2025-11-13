import os
import re
import time
from typing import Dict, List
from dotenv import load_dotenv
from crewai_tools import SerperDevTool
from crewai import LLM, Agent, Task, Crew
from routes.src.utils import _strip_step_number_prefix

load_dotenv()


class InvestigationStepLibrary:
    def __init__(self):
        self._init_llm()

        # Initialize web search if available
        try:
            self.web_search = SerperDevTool()
            self.has_web = True
            print("✅ Web search enabled for step generation")
        except:
            self.web_search = None
            self.has_web = False
            print("⚠️ Web search unavailable")

        print("✅ Dynamic Investigation Step Library initialized")

    def _init_llm(self):
        """Initialize LLM for step generation"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.llm = LLM(
                model="gemini/gemini-2.5-flash", api_key=gemini_key, temperature=0.3
            )
            print("✅ Using Gemini for step generation")
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.llm = LLM(
                model=ollama_model, base_url="http://localhost:11434", temperature=0.3
            )
            print(f"✅ Using {ollama_model} for step generation")

    def generate_steps_from_manual_analysis(
    self, alert_name: str, analysis_text: str, rule_number: str = "MANUAL_GEN", alert_data:dict=None
) -> List[Dict]:
        # ✅ ADD THIS DIAGNOSTIC
        print(f"\n🔍 DIAGNOSTIC: generate_steps_from_manual_analysis()")
        print(f"   alert_data type: {type(alert_data)}")
        print(f"   alert_data is None: {alert_data is None}")
        if alert_data:
            print(f"   alert_data keys: {list(alert_data.keys())}")
            entities = alert_data.get("entities", {})
            print(f"   entities type: {type(entities)}")
            if isinstance(entities, dict):
                print(f"   entities.entities count: {len(entities.get('entities', []))}")

        print(f"\n{'='*80}")
        print(f"🤖 GENERATING MANUAL ALERT INVESTIGATION STEPS")
        print(f"Alert: {alert_name}")
        print(f"{'='*80}\n")

        start_time = time.time()

        # STEP 1: Parse analysis to extract profile
        print("📊 PHASE 1: Analyzing alert structure...")
        profile = self._parse_alert_analysis(analysis_text, alert_name)

        # STEP 2: Research investigation methodologies using web search
        print("\n🌐 PHASE 2: Researching investigation best practices...")
        investigation_guidance = self._research_investigation_approach(
            alert_name, profile
        )

        # STEP 3: Generate 6-7 core investigation steps
        print("\n🧠 PHASE 3: Generating investigation steps...")
        generated_steps = self._generate_manual_investigation_steps(
            alert_name, profile, investigation_guidance
        )

        # ✅ NEW: STEP 3.5 - Remove AI-generated VIP/IP steps BEFORE deduplication
        print("\n🧹 PHASE 3.5: Removing AI-generated VIP/IP steps (will inject clean ones later)...")
        generated_steps = self._remove_duplicate_vip_and_ip_steps(generated_steps)

        # STEP 3.6: DEDUPLICATE REMAINING STEPS
        print("\n🧹 PHASE 3.6: Deduplicating remaining steps...")
        generated_steps = self._deduplicate_manual_steps(generated_steps)

        # STEP 4: Add VIP USER CHECK (MUST BE BEFORE IP REPUTATION)
        print("\n👤 PHASE 4: Adding VIP user verification step...")
        steps_with_vip = self._inject_vip_user_step(generated_steps, rule_number, alert_data)

        # STEP 5: Add IP REPUTATION CHECK
        print("\n🛡️ PHASE 5: Adding IP reputation verification step...")
        steps_with_ip = self._inject_ip_reputation_step(
            steps_with_vip, rule_number, alert_data
        )

        # STEP 6: Generate KQL for each step
        print("\n⚙️ PHASE 6: Generating KQL queries...")
        final_steps = self._add_kql_to_steps_enhanced(steps_with_ip, alert_name)

        # STEP 7: FILTER STEPS - Keep only those with KQL OR external tools
        print("\n🔍 PHASE 7: Validating steps (keeping those with queries or tools)...")
        cleaned_steps = self._filter_steps_by_kql_enhanced(final_steps)

        elapsed = time.time() - start_time
        print(f"\n{'='*80}")
        print(
            f"✅ COMPLETED in {elapsed:.1f}s: {len(cleaned_steps)} investigation steps"
        )
        print(f"{'='*80}\n")

        return cleaned_steps

    def _remove_duplicate_vip_and_ip_steps(self, steps: List[Dict]) -> List[Dict]:
        """
        Remove ALL AI-generated VIP/IP steps before injection
        ✅ ENHANCED: More aggressive matching to catch all variants
        """
        print("   🧹 Removing ALL AI-generated VIP/IP steps...")

        filtered_steps = []
        removed_count = 0

        for step in steps:
            step_name = _strip_step_number_prefix(step.get("step_name", "")).lower()
            explanation = step.get("explanation", "").lower()
            tool = step.get("tool", "").lower()

            # ✅ COMPREHENSIVE VIP DETECTION
            vip_keywords = [
                "vip", "high-priority", "high priority", "privileged account",
                "executive", "executive account", "verify user account status",
                "check user status", "user account verification", "account status"
            ]
            is_vip_step = any(keyword in step_name or keyword in explanation for keyword in vip_keywords)

            # ✅ COMPREHENSIVE IP REPUTATION DETECTION
            ip_keywords = [
                "ip reputation", "source ip reputation", "ip address reputation",
                "virustotal", "virus total", "abuseipdb", "abuse ipdb",
                "check ip", "verify ip", "validate ip", "threat intelligence"
            ]
            is_ip_step = any(keyword in step_name or keyword in explanation for keyword in ip_keywords)

            if is_vip_step:
                print(f"   ❌ Removing AI VIP step: {step.get('step_name', '')[:60]}")
                removed_count += 1
                continue

            if is_ip_step:
                print(f"   ❌ Removing AI IP step: {step.get('step_name', '')[:60]}")
                removed_count += 1
                continue

            # Keep all other steps
            filtered_steps.append(step)

        print(f"   ✅ Removed {removed_count} AI-generated VIP/IP steps")
        print(f"   ✅ Remaining steps: {len(filtered_steps)}")
        return filtered_steps

    def _filter_steps_by_kql_enhanced(self, steps: List[Dict]) -> List[Dict]:
        """
        Keep only steps that have KQL queries OR External tools OR special input requirements
        
        ✅ FIXED: Now preserves VIP user verification steps even if KQL is placeholder
        ✅ FIXED: Now preserves IP reputation steps with tool="virustotal"
        """
        print("   🔍 Filtering steps by KQL presence...")

        filtered_steps = []
        removed_count = 0

        for step in steps:
            step_name = _strip_step_number_prefix(step.get("step_name", ""))
            kql_query = step.get("kql_query", "").strip()
            tool = step.get("tool", "").strip().lower()
            input_required = step.get("input_required", "").strip()  # ✅ NEW: Check input_required

            # ============================================================
            # PRIORITY 1: Keep VIP user verification steps (by input_required flag)
            # ============================================================
            if input_required == "vip_user_list":
                filtered_steps.append(step)
                print(f"   ✅ Keeping VIP step: {step_name[:60]}")
                continue

            # ============================================================
            # PRIORITY 2: Keep IP reputation steps (by tool)
            # ============================================================
            if tool in ["virustotal", "abuseipdb"]:
                filtered_steps.append(step)
                print(f"   ✅ Keeping IP reputation step: {step_name[:60]} (Tool: {tool})")
                continue

            # ============================================================
            # PRIORITY 3: Keep steps with valid KQL queries (including placeholders)
            # ============================================================
            if kql_query and len(kql_query) > 30:
                # Check if it's a VIP placeholder query (additional safety check)
                if "<VIP_USER_LIST_PLACEHOLDER>" in kql_query:
                    filtered_steps.append(step)
                    print(f"   ✅ Keeping VIP step with placeholder: {step_name[:60]}")
                else:
                    filtered_steps.append(step)
                    print(f"   ✅ Keeping: {step_name[:60]} (has KQL - {len(kql_query)} chars)")
                continue

            # ============================================================
            # PRIORITY 4: Fallback - Check step name for VIP/IP keywords
            # ============================================================
            step_name_lower = step_name.lower()
            explanation = step.get("explanation", "").lower()

            # VIP step detection (safety net)
            vip_keywords = ["vip", "high-priority", "privileged account", "executive", "account status"]
            if any(kw in step_name_lower or kw in explanation for kw in vip_keywords):
                filtered_steps.append(step)
                print(f"   ✅ Keeping VIP step (by keyword): {step_name[:60]}")
                continue

            # IP reputation detection (safety net)
            ip_keywords = ["ip reputation", "virustotal", "abuseipdb", "threat intelligence"]
            if any(kw in step_name_lower or kw in explanation for kw in ip_keywords):
                filtered_steps.append(step)
                print(f"   ✅ Keeping IP step (by keyword): {step_name[:60]}")
                continue

            # ============================================================
            # REMOVE: Steps without KQL, tool, or special requirements
            # ============================================================
            print(f"   ⏭️  Removing: {step_name[:60]} (no KQL, no tool, no special input)")
            removed_count += 1

        print(f"   ✅ Filtered out {removed_count} steps without KQL or tools")
        print(f"   ✅ Final count: {len(filtered_steps)} investigation steps")

        return filtered_steps

    def _inject_vip_user_step(self, steps: List[Dict], rule_number: str, alert_data: dict = None) -> List[Dict]:
        """
        ✅ DIAGNOSTIC VERSION - Shows exactly why VIP step isn't being added
        """
        print(f"\n{'='*80}")
        print(f"🔍 VIP INJECTION DIAGNOSTIC")
        print(f"{'='*80}")

        # DIAGNOSTIC 1: Check alert_data
        print(f"\n1️⃣ Checking alert_data:")
        if alert_data is None:
            print(f"   ❌ alert_data is None!")
            print(f"   💡 VIP step requires alert_data to extract Account entities")
            return steps
        else:
            print(f"   ✅ alert_data exists")
            print(f"   📊 alert_data keys: {list(alert_data.keys())}")

        # DIAGNOSTIC 2: Check entities structure
        print(f"\n2️⃣ Checking entities structure:")
        entities = alert_data.get("entities", {})
        print(f"   📦 entities type: {type(entities)}")
        print(f"   📦 entities value: {entities if isinstance(entities, list) else 'dict with keys: ' + str(list(entities.keys()) if isinstance(entities, dict) else 'unknown')}")

        # Extract entities list
        if isinstance(entities, dict):
            entities_list = entities.get("entities", [])
            print(f"   📋 entities.entities list: {len(entities_list)} items")
        elif isinstance(entities, list):
            entities_list = entities
            print(f"   📋 entities is already a list: {len(entities_list)} items")
        else:
            entities_list = []
            print(f"   ⚠️  Unexpected entities type!")

        # DIAGNOSTIC 3: Check for Account entities
        print(f"\n3️⃣ Searching for Account entities:")
        has_account_entities = False
        account_count = 0

        for idx, entity in enumerate(entities_list):
            entity_kind = entity.get("kind", "").lower()
            print(f"   Entity {idx + 1}: kind='{entity_kind}'")

            if entity_kind == "account":
                has_account_entities = True
                account_count += 1
                props = entity.get("properties", {})
                account_name = props.get("accountName", "")
                upn_suffix = props.get("upnSuffix", "")
                print(f"      ✅ ACCOUNT FOUND: {account_name}@{upn_suffix}")

        print(f"\n4️⃣ Account entities summary:")
        print(f"   Total entities: {len(entities_list)}")
        print(f"   Account entities: {account_count}")
        print(f"   Has accounts: {has_account_entities}")

        # DIAGNOSTIC 4: Decision point
        print(f"\n5️⃣ Decision:")
        if not has_account_entities:
            print(f"   ❌ NO ACCOUNT ENTITIES → Skipping VIP step")
            print(f"   💡 VIP verification requires at least 1 Account entity")
            print(f"{'='*80}\n")
            return steps

        print(f"   ✅ ACCOUNT ENTITIES FOUND → Injecting VIP step")

        # DIAGNOSTIC 5: Create VIP step
        print(f"\n6️⃣ Creating VIP step:")

        placeholder_vip_kql = """// VIP User Verification Query - PLACEHOLDER
    // This query will be dynamically generated during triaging with:
    //   - VIP user list (provided by analyst)
    //   - Affected users (from alert entities)  
    //   - Alert timestamp (for accurate time range)

    let VIPUsers = datatable(UserPrincipalName:string)
    [
        "<VIP_USER_LIST_PLACEHOLDER>"
    ];
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where UserPrincipalName == "<USER_EMAIL>"
    | extend IsVIP = iff(UserPrincipalName in (VIPUsers), "⭐ VIP ACCOUNT", "Regular User")
    | summarize
        TotalSignIns = count(),
        UniqueIPAddresses = dcount(IPAddress),
        UniqueCountries = dcount(tostring(LocationDetails.countryOrRegion)),
        HighRiskSignIns = countif(RiskLevelAggregated == "high"),
        MediumRiskSignIns = countif(RiskLevelAggregated == "medium"),
        FailedAttempts = countif(ResultType != "0"),
        SuccessfulSignIns = countif(ResultType == "0")
        by UserPrincipalName, UserDisplayName, IsVIP
    | extend
        VIPRiskScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedAttempts * 2) + (UniqueCountries * 3)
    | extend
        AccountClassification = case(
            VIPRiskScore > 30, "🔴 Critical - Executive at High Risk",
            VIPRiskScore > 15, "🟠 High - VIP Requires Attention",
            VIPRiskScore > 5, "🟡 Medium - Monitor Closely", 
            "🟢 Low - Normal Activity"
        )
    | project-reorder UserPrincipalName, UserDisplayName, IsVIP, AccountClassification, VIPRiskScore
    | order by VIPRiskScore desc"""

        vip_step = {
            "step_name": "Verify User Account Status and Check if Account is VIP or High-Priority",
            "explanation": "This step analyzes the affected user account to determine their role, privileges, and organizational importance. You will be prompted to provide a list of known VIP users (executives, admins, high-value accounts). The KQL query will then check if the affected users are in the VIP list and assess their risk level based on sign-in patterns, geographic locations, and risk indicators.",
            "relevance": "VIP/privileged accounts have access to sensitive data and systems. Compromise of such accounts represents a critical security incident requiring immediate escalation and response.",
            "data_source": "SigninLogs",
            "priority": "HIGH",
            "tool": "",
            "input_required": "vip_user_list",  # ✅ CRITICAL FLAG
            "source": "ai_generated",
            "confidence": "HIGH",
            "kql_query": placeholder_vip_kql,
            "kql_explanation": "Queries SigninLogs to check if affected users are VIP accounts and analyzes their activity patterns, risk levels, and geographic locations. The VIP user list and exact time ranges will be dynamically injected during triaging.",
        }

        print(f"   ✅ VIP step created:")
        print(f"      step_name: {vip_step['step_name'][:60]}...")
        print(f"      input_required: '{vip_step['input_required']}'")
        print(f"      kql_query length: {len(vip_step['kql_query'])} chars")
        print(f"      Has placeholder: {'<VIP_USER_LIST_PLACEHOLDER>' in vip_step['kql_query']}")

        # DIAGNOSTIC 6: Insert position
        insert_position = min(2, len(steps))
        print(f"\n7️⃣ Inserting VIP step:")
        print(f"   Current step count: {len(steps)}")
        print(f"   Insert position: {insert_position + 1}")

        steps.insert(insert_position, vip_step)

        print(f"   ✅ VIP step inserted successfully")
        print(f"   New step count: {len(steps)}")
        print(f"{'='*80}\n")

        return steps

    def _inject_ip_reputation_step(self, steps: List[Dict], rule_number: str, alert_data: dict = None) -> List[Dict]:
        """
        ✅ DIAGNOSTIC VERSION - Shows exactly why IP step isn't being added
        """
        print(f"\n{'='*80}")
        print(f"🔍 IP INJECTION DIAGNOSTIC")
        print(f"{'='*80}")

        # DIAGNOSTIC 1: Check alert_data
        print(f"\n1️⃣ Checking alert_data:")
        if alert_data is None:
            print(f"   ❌ alert_data is None!")
            print(f"   💡 IP step requires alert_data to extract IP entities")
            return steps
        else:
            print(f"   ✅ alert_data exists")

        # DIAGNOSTIC 2: Check entities structure
        print(f"\n2️⃣ Checking entities structure:")
        entities = alert_data.get("entities", {})

        if isinstance(entities, dict):
            entities_list = entities.get("entities", [])
        elif isinstance(entities, list):
            entities_list = entities
        else:
            entities_list = []

        print(f"   📋 Total entities: {len(entities_list)}")

        # DIAGNOSTIC 3: Check for IP entities
        print(f"\n3️⃣ Searching for IP entities:")
        has_ip_entities = False
        ip_count = 0

        for idx, entity in enumerate(entities_list):
            entity_kind = entity.get("kind", "").lower()
            print(f"   Entity {idx + 1}: kind='{entity_kind}'")

            if entity_kind == "ip":
                has_ip_entities = True
                ip_count += 1
                props = entity.get("properties", {})
                ip_address = props.get("address", "")
                print(f"      ✅ IP FOUND: {ip_address}")

        print(f"\n4️⃣ IP entities summary:")
        print(f"   IP entities: {ip_count}")
        print(f"   Has IPs: {has_ip_entities}")

        # DIAGNOSTIC 4: Decision
        print(f"\n5️⃣ Decision:")
        if not has_ip_entities:
            print(f"   ❌ NO IP ENTITIES → Skipping IP step")
            print(f"{'='*80}\n")
            return steps

        print(f"   ✅ IP ENTITIES FOUND → Injecting IP step")

        # Create IP step
        ip_step = {
            "step_name": "Check Source IP Reputation & VPN/Proxy Detection Using VirusTotal, AbuseIPDB and Abstract API",
            "explanation": "This step validates the reputation of source IP addresses using external threat intelligence platforms (VirusTotal, AbuseIPDB and Abstract API) and detects VPN/proxy/Tor usage to identify if the IPs are associated with known malicious activity or anonymization services. IPs are automatically extracted from alert entities. Look for high detection ratios (5+ vendors), recent abuse reports, VPN/proxy flags, Tor exit nodes, or associations with known threat actors.",
            "relevance": "IP reputation and VPN detection provide immediate validation of the threat level. A malicious source IP or VPN/Tor usage strongly indicates suspicious activity that requires further investigation.",
            "data_source": "Manual",
            "priority": "CRITICAL",
            "tool": "virustotal",
            "input_required": "",
            "source": "ai_generated",
            "confidence": "HIGH",
            "kql_query": "",
            "kql_explanation": "Requires manual checking using external tools (VirusTotal, AbuseIPDB, Abstract API) or the integrated IP reputation & VPN detection checker in the triaging app.",
        }

        insert_position = min(3, len(steps))
        print(f"\n6️⃣ Inserting IP step at position {insert_position + 1}")
        steps.insert(insert_position, ip_step)
        print(f"   ✅ IP step inserted")
        print(f"{'='*80}\n")

        return steps

    def _add_kql_to_steps_enhanced(
        self, steps: List[Dict], alert_name: str
    ) -> List[Dict]:
        """
        Generate KQL queries for each step
        ✅ FIXED: Preserve VIP placeholder query and prevent hardcoded query replacement
        """
        from routes.src.api_kql_generation import EnhancedKQLGenerator

        kql_gen = EnhancedKQLGenerator()

        for idx, step in enumerate(steps, 1):
            # ============================================================
            # PRIORITY 1: Handle VIP steps FIRST - preserve placeholder
            # ============================================================
            input_required = step.get("input_required", "")
            if input_required == "vip_user_list":
                existing_query = step.get("kql_query", "").strip()

                # Check if placeholder already exists
                if "<VIP_USER_LIST_PLACEHOLDER>" in existing_query:
                    print(
                        f"   ✅ VIP step {idx} - preserving placeholder query for dynamic injection"
                    )
                    # DON'T touch it - preserve the placeholder for triaging to replace
                    continue
                else:
                    # Fallback: if somehow placeholder is missing, skip and log warning
                    print(
                        f"   ⚠️  VIP step {idx} - placeholder missing, skipping KQL generation"
                    )
                    continue

            # ============================================================
            # PRIORITY 2: Skip external tools
            # ============================================================
            tool = step.get("tool", "").lower()
            if tool in ["virustotal", "abuseipdb"]:
                print(f"   ⏭️  Skipping KQL for step {idx} (External Tool: {tool})")
                continue

            # ============================================================
            # PRIORITY 3: Skip if already has valid KQL (non-placeholder)
            # ============================================================
            existing_query = step.get("kql_query", "").strip()
            if existing_query and len(existing_query) > 30:
                # Make sure it's not a placeholder template
                if "<VIP_USER_LIST_PLACEHOLDER>" not in existing_query:
                    print(f"   ✅ Step {idx} already has KQL")
                    continue

            # ============================================================
            # Generate KQL for remaining steps
            # ============================================================
            step_name = _strip_step_number_prefix(step.get("step_name", ""))
            explanation = step.get("explanation", "")

            print(f"   🔧 Generating KQL for step {idx}: {step_name[:50]}...")

            # ✅ SPECIAL HANDLING: Force KQL for geography/location steps
            combined = f"{step_name} {explanation}".lower()
            is_geography_step = any(
                keyword in combined
                for keyword in [
                    "geographic",
                    "geography",
                    "location",
                    "impossible travel",
                    "geo",
                    "country",
                    "city",
                    "region",
                ]
            )

            # Try to generate KQL
            kql_query, kql_explanation = kql_gen.generate_kql_query(
                step_name=step_name,
                explanation=explanation,
                rule_context=alert_name,
            )

            # ✅ VALIDATION: Check if KQL was actually generated
            if kql_query and len(kql_query.strip()) > 30:
                step["kql_query"] = kql_query
                step["kql_explanation"] = kql_explanation
                print(f"      ✅ KQL generated ({len(kql_query)} chars)")
            else:
                # ✅ FOR GEOGRAPHY STEPS: Provide fallback KQL if API fails
                if is_geography_step:
                    print(f"      🌍 Geography step detected - using fallback KQL")
                    step["kql_query"] = self._get_geography_fallback_kql()
                    step["kql_explanation"] = (
                        "Queries SigninLogs to identify sign-ins from unusual geographic locations by analyzing Location and IPAddress fields."
                    )
                    print(f"      ✅ Fallback geography KQL applied")
                else:
                    print(f"      ⚠️  KQL generation failed for: {step_name[:50]}")
                    step["kql_query"] = ""
                    step["kql_explanation"] = ""

        print("\n   🧹 Deduplicating KQL queries...")
        deduplicated_steps = kql_gen._deduplicate_queries_in_template(steps)

        return deduplicated_steps

    def _get_geography_fallback_kql(self) -> str:
        """Fallback KQL for geographic analysis steps"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| summarize 
    SignInCount = count(),
    UniqueLocations = dcount(Country),
    Countries = make_set(Country),
    Cities = make_set(City)
    by UserPrincipalName, IPAddress
| where UniqueLocations >= 1
| project UserPrincipalName, IPAddress, Countries, Cities, SignInCount, UniqueLocations
| order by UniqueLocations desc"""

    def _deduplicate_manual_steps(self, steps: List[Dict]) -> List[Dict]:
        """Remove duplicate steps based on step name similarity"""
        from difflib import SequenceMatcher

        print("   🔍 Checking for duplicates...")

        unique_steps = []
        seen_names = []
        duplicates_removed = 0

        for step in steps:
            step_name = _strip_step_number_prefix(step.get("step_name", "")).lower().strip()

            if not step_name or len(step_name) < 5:
                continue

            is_duplicate = False
            for seen_name in seen_names:
                similarity = SequenceMatcher(None, step_name, seen_name).ratio()

                if similarity > 0.7:
                    print(f"   ⏭️  Removing duplicate: '{step_name[:60]}'")
                    duplicates_removed += 1
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique_steps.append(step)
                seen_names.append(step_name)

        print(f"   ✅ Removed {duplicates_removed} duplicate steps")
        return unique_steps

    def _parse_alert_analysis(self, analysis_text: str, alert_name: str) -> Dict:
        """Parse AI analysis to extract structured profile"""
        print("   🔍 Extracting technical details...")

        profile = {
            "alert_name": alert_name,
            "technical_overview": "",
            "mitre_techniques": [],
            "mitre_details": {},
            "threat_actors": [],
            "threat_ttps": {},
            "business_impact": [],
            "detection_mechanisms": [],
            "data_sources": [],
        }

        # Extract Technical Overview
        tech_match = re.search(
            r"##\s*TECHNICAL\s*OVERVIEW\s*(.*?)(?=##|\Z)",
            analysis_text,
            re.IGNORECASE | re.DOTALL,
        )
        if tech_match:
            overview = tech_match.group(1).strip()
            overview = re.sub(r"\n{2,}", " ", overview)[:800]
            profile["technical_overview"] = overview
            print(f"   ✅ Technical overview extracted")

        # Extract MITRE ATT&CK Techniques
        mitre_section = re.search(
            r"##\s*MITRE\s*ATT&CK.*?(?=##|\Z)",
            analysis_text,
            re.IGNORECASE | re.DOTALL,
        )
        if mitre_section:
            mitre_text = mitre_section.group(0)
            techniques = re.findall(
                r"(T\d{4}(?:\.\d{3})?)\s*[-–:]*\s*([^\n]+)", mitre_text
            )
            for tech_id, tech_name in techniques[:4]:
                profile["mitre_techniques"].append(tech_id)
                profile["mitre_details"][tech_id] = tech_name.strip()
            print(f"   ✅ MITRE Techniques: {len(profile['mitre_techniques'])}")

        # Extract Threat Actors
        actor_section = re.search(
            r"##\s*THREAT\s*ACTORS.*?(?=##|\Z)",
            analysis_text,
            re.IGNORECASE | re.DOTALL,
        )
        if actor_section:
            actor_text = actor_section.group(0)
            actors = re.findall(r"###\s*([^\(\n]+?)(?:\s*\([^\)]+\))?", actor_text)
            profile["threat_actors"] = [a.strip() for a in actors[:3]]

            for actor in profile["threat_actors"]:
                ttps_match = re.search(
                    rf"###\s*{re.escape(actor)}.*?(?:TTPs?|Methods?):\s*([^\n]+)",
                    actor_text,
                    re.IGNORECASE | re.DOTALL,
                )
                if ttps_match:
                    profile["threat_ttps"][actor] = ttps_match.group(1).strip()
            print(f"   ✅ Threat Actors: {len(profile['threat_actors'])}")

        # Detect data sources from technical content
        tech_lower = profile["technical_overview"].lower()
        if "signinlogs" in tech_lower:
            profile["data_sources"].append("SigninLogs")
        if "auditlogs" in tech_lower:
            profile["data_sources"].append("AuditLogs")
        if "deviceinfo" in tech_lower:
            profile["data_sources"].append("DeviceInfo")
        if "cloudappevents" in tech_lower:
            profile["data_sources"].append("CloudAppEvents")

        if not profile["data_sources"]:
            profile["data_sources"] = ["SigninLogs", "AuditLogs"]

        return profile

    def _research_investigation_approach(self, alert_name: str, profile: Dict) -> str:
        """Research investigation methodologies using web search + LLM"""
        print("   🔎 Searching for investigation methodologies...")

        if not self.has_web:
            print("   ⚠️ Web search unavailable, using LLM analysis only")
            return self._analyze_without_web_search(alert_name, profile)

        search_queries = []

        # Query 1: Alert-specific playbook
        search_queries.append(
            f"{alert_name} SOC investigation playbook incident response procedure"
        )

        # Query 2: MITRE technique investigation
        if profile.get("mitre_techniques"):
            primary_technique = profile["mitre_techniques"][0]
            tech_name = profile["mitre_details"].get(primary_technique, "")
            search_queries.append(
                f"MITRE {primary_technique} {tech_name} detection investigation methodology"
            )

        all_findings = []

        for query in search_queries[:2]:
            try:
                print(f"   🌐 Searching: {query[:60]}...")
                agent = Agent(
                    role="Security Research Analyst",
                    goal=f"Research investigation methodology",
                    backstory="Expert at finding SOC investigation best practices",
                    tools=[self.web_search],
                    llm=self.llm,
                    verbose=False,
                    max_iter=5,
                )

                task = Task(
                    description=f"""Search for: {query}

Extract:
1. Investigation steps SOC analysts should follow
2. Specific data sources and log types to check
3. Key indicators and artifacts to look for

Return ONLY actionable investigation procedures as bullet points.""",
                    expected_output="Concise bullet point list of investigation steps",
                    agent=agent,
                )

                crew = Crew(agents=[agent], tasks=[task], verbose=False)
                result = crew.kickoff()

                findings = str(result).strip()
                if findings and len(findings) > 100:
                    all_findings.append(findings)
                    print(f"   ✅ Found guidance")

            except Exception as e:
                print(f"   ⚠️ Search failed: {str(e)[:80]}")
                continue

        return "\n\n".join(all_findings) if all_findings else ""

    def _analyze_without_web_search(self, alert_name: str, profile: Dict) -> str:
        """Fallback analysis using LLM when web search unavailable"""
        try:
            prompt = f"""Based on security threat knowledge, outline investigation procedures for:

Alert: {alert_name}
MITRE Techniques: {', '.join(profile.get('mitre_techniques', []))}

Provide investigation procedures focusing on data sources and key indicators."""

            agent = Agent(
                role="SOC Analyst",
                goal="Provide investigation procedures",
                backstory="Expert security analyst",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Investigation procedures",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            return str(crew.kickoff())

        except Exception as e:
            print(f"   ⚠️ Analysis failed: {str(e)[:80]}")
            return ""

    def _generate_manual_investigation_steps(
        self, alert_name: str, profile: Dict, guidance: str
    ) -> List[Dict]:
        """Generate 6-7 investigation steps using LLM + profile + guidance"""
        print("   🧠 Generating investigation steps...")

        prompt = f"""Generate 6-7 UNIQUE investigation steps for this security alert.

ALERT: {alert_name}

TECHNICAL CONTEXT:
{profile.get('technical_overview', '')[:600]}

GENERATE 6-7 INVESTIGATION STEPS covering:
1. Scope verification - how many users/systems affected
2. Authentication analysis - examine sign-in patterns
3. Geographic analysis - check for unusual locations or impossible travel
4. Threat intelligence - verify external indicators  
5. Behavioral analysis - identify anomalies
6. Device/Endpoint analysis - verify device health

CRITICAL REQUIREMENTS:
- Each step MUST be UNIQUE and check DIFFERENT data
- Steps should require KQL queries (SigninLogs/AuditLogs/DeviceInfo)
- Include geographic/location analysis step
- Be specific about WHAT to examine and WHY

FORMAT EACH STEP AS:
STEP: [Descriptive name]
EXPLANATION: [What to examine, why it matters, what to find]
DATA_SOURCE: [SigninLogs/AuditLogs/DeviceInfo]
PRIORITY: [CRITICAL/HIGH/MEDIUM]
TOOL: [None unless IP reputation check]
RELEVANCE: [How this helps investigate THIS alert]
---

Generate NOW:"""

        agent = Agent(
            role="SOC Investigation Playbook Expert",
            goal="Generate 6-7 unique investigation steps",
            backstory="Expert at creating comprehensive investigation workflows",
            llm=self.llm,
            verbose=False,
        )

        task = Task(
            description=prompt,
            expected_output="6-7 investigation steps with all required fields",
            agent=agent,
        )

        crew = Crew(agents=[agent], tasks=[task], verbose=False)
        result = str(crew.kickoff())

        return self._parse_manual_steps(result)

    def _parse_manual_steps(self, llm_output: str) -> List[Dict]:
        """Parse LLM output into structured steps"""
        steps = []
        step_blocks = re.split(r"\n[-=_]{3,}\n", llm_output)

        for block in step_blocks:
            if not block.strip() or len(block) < 50:
                continue

            step_match = re.search(r"STEP:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            exp_match = re.search(
                r"EXPLANATION:\s*(.+?)(?=\n(?:DATA_SOURCE|PRIORITY|TOOL|RELEVANCE)|$)",
                block,
                re.IGNORECASE | re.DOTALL,
            )
            ds_match = re.search(r"DATA_SOURCE:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            priority_match = re.search(
                r"PRIORITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)",
                block,
                re.IGNORECASE,
            )
            tool_match = re.search(r"TOOL:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            relevance_match = re.search(
                r"RELEVANCE:\s*(.+?)(?=\n(?:STEP|---)|$)",
                block,
                re.IGNORECASE | re.DOTALL,
            )

            if step_match and exp_match:
                step_name = self._clean_text(step_match.group(1))
                explanation = self._clean_text(exp_match.group(1))
                data_source = ds_match.group(1).strip() if ds_match else "SigninLogs"
                priority = (
                    priority_match.group(1).upper() if priority_match else "MEDIUM"
                )
                tool = tool_match.group(1).strip() if tool_match else "None"
                relevance = (
                    self._clean_text(relevance_match.group(1))
                    if relevance_match
                    else ""
                )

                explanation = re.sub(r"\s+", " ", explanation)
                relevance = re.sub(r"\s+", " ", relevance)

                if len(step_name) < 5 or len(explanation) < 30:
                    continue

                steps.append(
                    {
                        "step_name": step_name,
                        "explanation": explanation,
                        "relevance": relevance,
                        "data_source": data_source,
                        "priority": priority,
                        "tool": tool.lower() if tool.lower() != "none" else "",
                        "input_required": "",
                        "source": "ai_generated",
                        "confidence": "HIGH",
                    }
                )

        return steps

    def _clean_text(self, text: str) -> str:
        """Clean text from artifacts"""
        text = text.strip("\"'`")
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"__", "", text)
        text = re.sub(r"^\*\s+", "", text)
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"^(Step \d+:|STEP:)", "", text, flags=re.IGNORECASE)
        return text.strip()

    def generate_investigation_steps(self, profile: Dict) -> List[Dict]:
        """Generate investigation steps for template-based generation"""
        print(f"\n🔬 Generating investigation steps for {profile['alert_name']}")

        # Research best practices if web search available
        investigation_guidance = ""
        if self.has_web:
            investigation_guidance = self._research_investigation_practices(profile)

        # Generate steps using LLM
        generated_steps = self._generate_steps_with_llm(profile, investigation_guidance)

        print(f"   ✅ Generated {len(generated_steps)} investigation steps")
        return generated_steps

    def _research_investigation_practices(self, profile: Dict) -> str:
        """Use web search to find investigation best practices"""
        print(f"   🌐 Researching investigation practices...")

        alert_name = profile.get("alert_name", "")
        mitre_techniques = profile.get("mitre_techniques", [])
        threat_actors = profile.get("threat_actors", [])

        search_queries = []

        if alert_name:
            search_queries.append(
                f"how to investigate {alert_name} SOC playbook incident response"
            )

        if mitre_techniques:
            primary_technique = mitre_techniques[0]
            tech_name = profile.get("mitre_details", {}).get(primary_technique, "")
            search_queries.append(
                f"MITRE {primary_technique} {tech_name} detection investigation steps"
            )

        if threat_actors:
            primary_actor = threat_actors[0]
            search_queries.append(
                f"{primary_actor} threat actor investigation detection methods"
            )

        all_findings = []

        for query in search_queries[:2]:
            try:
                agent = Agent(
                    role="Security Research Analyst",
                    goal=f"Research investigation methodology for: {query}",
                    backstory="Expert at finding SOC investigation best practices and playbooks",
                    tools=[self.web_search],
                    llm=self.llm,
                    verbose=False,
                    max_iter=5,
                )

                task = Task(
                    description=f"""Search the web for: {query}

Find and extract:
1. Key investigation steps and procedures
2. Data sources and logs to check
3. Tools and techniques to use
4. Indicators to look for
5. Common artifacts and evidence

Return ONLY the actionable investigation steps as concise bullet points.
Focus on what a SOC analyst should DO, not just theory.""",
                    expected_output="Concise bullet point list of investigation steps",
                    agent=agent,
                )

                crew = Crew(agents=[agent], tasks=[task], verbose=False)
                result = crew.kickoff()

                findings = str(result).strip()
                if findings and len(findings) > 50:
                    all_findings.append(findings)
                    print(f"   ✅ Found guidance: {query[:60]}...")

            except Exception as e:
                print(f"   ⚠️ Search failed: {str(e)[:80]}")
                continue

        return "\n\n".join(all_findings) if all_findings else ""

    def _generate_steps_with_llm(self, profile: Dict, guidance: str) -> List[Dict]:
        """Generate investigation steps with STRICT anti-duplication"""

        existing_steps = profile.get("existing_step_names", [])
        existing_str = (
            "\n".join([f"- {s}" for s in existing_steps]) if existing_steps else "None"
        )

        prompt = f"""Generate NEW investigation steps that DON'T duplicate these existing ones:

EXISTING STEPS (DO NOT REPEAT):
{existing_str}

ALERT: {profile.get('alert_name', '')}
ALERT TYPE: {profile.get('alert_type', '')}
TECHNICAL OVERVIEW: {profile.get('technical_overview', '')[:600]}

CRITICAL ANTI-DUPLICATION RULES:
1. If "user count" or "impacted users" exists, DO NOT generate "Determine Total Number of Users"
2. If "IP reputation" or "IP validation" exists, DO NOT generate IP reputation steps
3. If "VIP users" exists, DO NOT generate user context steps
4. Generate ONLY truly unique steps that investigate DIFFERENT aspects

REQUIRED NEW STEPS (generate 3-4 UNIQUE ones that address gaps):
Focus on aspects NOT covered by existing steps:
- Advanced behavioral analysis (time patterns, impossible travel, unusual hours)
- Credential usage analysis (password sprays, brute force attempts, account lockouts)
- Session analysis (concurrent logins, session hijacking, session duration)
- Application access patterns (risky apps, OAuth grants, sensitive data access)
- Privilege escalation checks (role changes, permission grants, admin actions)
- Conditional access policy violations (bypassed policies, risky sign-ins)

Each step MUST:
1. NOT duplicate existing steps
2. Have specific, descriptive name (10-15 words explaining WHAT you're checking)
3. Target a different data aspect than existing steps
4. Require KQL query (SigninLogs/AuditLogs/DeviceInfo/CloudAppEvents)
5. Explain in SIMPLE language WHY this matters for THIS alert

FORMAT (follow exactly):
STEP: [Descriptive name: "Check for X to detect Y behavior"]
EXPLANATION: [3 parts in simple language:
1. WHAT to check: "This step examines [specific data/logs]..."
2. WHY it matters: "This is important because [how it relates to the alert]..."
3. WHAT to look for: "Look for [specific indicators like X, Y, Z]..."]
NEEDS_KQL: [YES/NO]
DATA_SOURCE: [SigninLogs/AuditLogs/DeviceInfo/CloudAppEvents]
TOOL: [None]
PRIORITY: [CRITICAL/HIGH/MEDIUM]
RELEVANCE: [How this step specifically helps investigate THIS alert]
---

Generate 3-4 UNIQUE, RELEVANT steps NOW:"""

        agent = Agent(
            role="SOC Investigation Playbook Designer",
            goal="Generate 3-4 unique investigation steps that don't duplicate existing ones",
            backstory="Expert at identifying gaps in investigation coverage and avoiding duplicates",
            llm=self.llm,
            verbose=False,
        )

        task = Task(
            description=prompt,
            expected_output="3-4 unique investigation steps",
            agent=agent,
        )
        crew = Crew(agents=[agent], tasks=[task], verbose=False)
        result = str(crew.kickoff())

        steps = self._parse_llm_steps(result)

        # Post-filter against existing
        unique_steps = []
        for step in steps:
            if not self._is_duplicate_of_existing(step, existing_steps):
                unique_steps.append(step)
            else:
                print(f"   ⏭️  Filtered duplicate: {step.get('step_name', '')[:60]}")

        return unique_steps

    def _parse_llm_steps(self, llm_output: str) -> List[Dict]:
        """Parse LLM output into structured step dictionaries"""
        steps = []
        step_blocks = re.split(r"\n[-=_]{3,}\n", llm_output)

        for block in step_blocks:
            if not block.strip() or len(block) < 50:
                continue

            step_match = re.search(r"STEP:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            exp_match = re.search(
                r"EXPLANATION:\s*(.+?)(?=\n(?:NEEDS_KQL|DATA_SOURCE|TOOL|PRIORITY|RELEVANCE)|$)",
                block,
                re.IGNORECASE | re.DOTALL,
            )
            kql_match = re.search(r"NEEDS_KQL:\s*(YES|NO)", block, re.IGNORECASE)
            ds_match = re.search(r"DATA_SOURCE:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            tool_match = re.search(r"TOOL:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            priority_match = re.search(
                r"PRIORITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)", block, re.IGNORECASE
            )
            relevance_match = re.search(
                r"RELEVANCE:\s*(.+?)(?=\n(?:STEP|---)|$)",
                block,
                re.IGNORECASE | re.DOTALL,
            )

            if step_match and exp_match:
                step_name = step_match.group(1).strip()
                explanation = exp_match.group(1).strip()
                needs_kql = kql_match.group(1).upper() == "YES" if kql_match else True
                data_source = ds_match.group(1).strip() if ds_match else "SigninLogs"
                tool = tool_match.group(1).strip() if tool_match else "None"
                priority = (
                    priority_match.group(1).upper() if priority_match else "MEDIUM"
                )
                relevance = relevance_match.group(1).strip() if relevance_match else ""

                # Clean up
                step_name = self._clean_text(step_name)
                explanation = self._clean_text(explanation)
                relevance = self._clean_text(relevance)

                # Validation
                if len(step_name) < 5 or len(explanation) < 20:
                    continue

                # Remove line breaks
                explanation = re.sub(r"\s+", " ", explanation)
                relevance = re.sub(r"\s+", " ", relevance)

                steps.append(
                    {
                        "step_name": step_name,
                        "explanation": explanation,
                        "relevance": relevance,
                        "kql_needed": needs_kql,
                        "data_source": data_source,
                        "tool": tool.lower() if tool.lower() != "none" else "",
                        "priority": priority,
                        "input_required": "",
                    }
                )

        return steps

    def _is_duplicate_of_existing(self, step: Dict, existing_names: List[str]) -> bool:
        """Check if step duplicates existing steps"""
        step_name = _strip_step_number_prefix(step.get("step_name", "")).lower()

        from difflib import SequenceMatcher

        for existing in existing_names:
            existing_lower = existing.lower()
            similarity = SequenceMatcher(None, step_name, existing_lower).ratio()

            if similarity > 0.6:
                return True

            step_keywords = set(step_name.split())
            existing_keywords = set(existing_lower.split())
            common = step_keywords & existing_keywords

            if len(common) >= 3:
                return True

        return False
