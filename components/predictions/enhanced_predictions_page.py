import os
import json
import hashlib
import traceback
import streamlit as st
import concurrent.futures
from datetime import datetime
from components.predictions.ip_analysis import analyze_ip_entities_parallel
from api_client.predictions_api_client import get_predictions_client
from components.triaging.step2_enhance import _upload_to_predictions_api
from components.predictions.enhanced_display_utils import display_enhanced_entity_analysis


def analyze_entities_parallel_enhanced(account_entities: list, client):
    """Enhanced parallel analysis with better progress tracking and error handling"""

    # Build username list
    usernames = []
    for entity in account_entities:
        props = entity.get("properties", {})
        account_name = props.get("accountName", "")
        upn_suffix = props.get("upnSuffix", "")

        if account_name and upn_suffix:
            username = f"{account_name}@{upn_suffix}"
        else:
            username = props.get("friendlyName", "Unknown")

        usernames.append(username)

    # Enhanced progress tracking
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 1rem; border-radius: 8px; margin: 1rem 0;">
            <h3 style="color: white; text-align: center; margin: 0;">
                🤖 Running Parallel Analysis for All Accounts
            </h3>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    progress_container = st.container()
    with progress_container:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Create columns for real-time status
        col1, col2, col3 = st.columns(3)
        with col1:
            completed_metric = st.empty()
        with col2:
            success_metric = st.empty()
        with col3:
            error_metric = st.empty()

    # Results container
    results = {}
    completed_count = 0
    success_count = 0
    error_count = 0

    def analyze_single_entity(username: str):
        """Analyze single entity with enhanced error handling"""
        cache_key = (
            f"entity_prediction_{username}_{hashlib.md5(username.encode()).hexdigest()}"
        )

        # Check cache first
        if cache_key in st.session_state:
            return username, st.session_state[cache_key]

        try:
            complete_analysis = client.analyze_complete(username)

            if complete_analysis.get("success"):
                st.session_state[cache_key] = complete_analysis
                return username, complete_analysis
            else:
                error_msg = complete_analysis.get("error", "Unknown error")
                if "No investigation data found" in error_msg or "404" in str(
                    error_msg
                ):
                    return username, {"error": "no_data", "username": username}
                else:
                    return username, {"error": error_msg, "username": username}
        except Exception as e:
            error_str = str(e)
            if "404" in error_str or "No investigation data" in error_str:
                return username, {"error": "no_data", "username": username}
            else:
                return username, {"error": str(e), "username": username}

    # Execute parallel analysis with enhanced tracking
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(analyze_single_entity, username): username
            for username in usernames
        }

        total = len(futures)

        for future in concurrent.futures.as_completed(futures):
            username = futures[future]
            try:
                username, result = future.result()
                results[username] = result
                completed_count += 1
                
                if "error" not in result:
                    success_count += 1
                else:
                    error_count += 1

                # Update progress
                progress_bar.progress(completed_count / total)
                status_text.text(f"Analyzing {username}... ({completed_count}/{total})")
                
                # Update metrics
                completed_metric.metric("Completed", f"{completed_count}/{total}")
                success_metric.metric("Successful", success_count)
                error_metric.metric("Errors", error_count)

            except Exception as e:
                results[username] = {"error": str(e), "username": username}
                completed_count += 1
                error_count += 1
                
                progress_bar.progress(completed_count / total)
                completed_metric.metric("Completed", f"{completed_count}/{total}")
                success_metric.metric("Successful", success_count)
                error_metric.metric("Errors", error_count)

    # Clear progress indicators
    progress_container.empty()
    
    # Enhanced completion message
    if success_count > 0:
        st.success(f"✅ Analysis complete! Successfully analyzed {success_count} accounts.")
    if error_count > 0:
        st.warning(f"⚠️ {error_count} accounts had issues during analysis.")
    
    st.markdown("---")

    # Enhanced results display with better organization
    st.markdown(
        """
        <div style="background: #f8fafc; border: 2px solid #e2e8f0; 
                   border-radius: 8px; padding: 1rem; margin: 1rem 0;">
            <h2 style="color: #374151; margin: 0; text-align: center;">
                📊 Investigation Results Summary
            </h2>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Separate results by type for better organization
    true_positives = []
    false_positives = []
    errors = []
    no_data = []

    for username in usernames:
        result = results.get(username, {})
        
        if "error" in result:
            if result["error"] == "no_data":
                no_data.append((username, result))
            else:
                errors.append((username, result))
        else:
            classification = result.get("initial_analysis", {}).get("classification", "")
            if "TRUE POSITIVE" in classification:
                true_positives.append((username, result))
            else:
                false_positives.append((username, result))

    # Display summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🚨 True Positives", len(true_positives))
    with col2:
        st.metric("✅ False Positives", len(false_positives))
    with col3:
        st.metric("ℹ️ No Data", len(no_data))
    with col4:
        st.metric("❌ Errors", len(errors))

    st.markdown("---")

    # Display results in priority order: True Positives first, then others
    all_results = true_positives + false_positives + [(u, r) for u, r in zip(usernames, [results.get(u, {}) for u in usernames]) if (u, r) not in true_positives + false_positives and "error" not in r]
    
    for username, result in all_results:
        if "error" not in result:
            display_enhanced_entity_analysis(username, result)

    # Display errors and no-data cases at the end
    if no_data:
        st.markdown("### ℹ️ Accounts with No Investigation Data")
        for username, result in no_data:
            with st.expander(f"👤 {username} - ℹ️ No Data", expanded=False):
                st.info(
                    f"No specific investigation data found for {username}. "
                    "This account may not have been directly involved in the investigation steps."
                )

    if errors:
        st.markdown("### ❌ Analysis Errors")
        for username, result in errors:
            with st.expander(f"👤 {username} - ❌ Error", expanded=False):
                st.error(f"Analysis failed: {result['error']}")


def display_enhanced_predictions_tab():
    """Enhanced predictions analysis tab with better structure and UI"""

    if not st.session_state.get("triaging_complete", False):
        st.markdown(
            """
            <div style="background: #fed7aa; border: 2px solid #f59e0b; 
                       border-radius: 8px; padding: 1.5rem; margin: 1rem 0; text-align: center;">
                <h3 style="color: #f59e0b; margin: 0 0 0.5rem 0;">⚠️ Triaging Required</h3>
                <p style="color: #92400e; margin: 0;">
                    Complete the AI Triaging workflow first to unlock predictions analysis
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    # Enhanced header
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 2rem; border-radius: 15px; margin: 1rem 0; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 2.5rem;">
                🔮 True/False Positive Analyzer with MITRE ATT&CK
            </h1>
            <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 1.2rem;">
                Advanced Security Investigation Analysis Engine
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Get alert data
    alert_data = st.session_state.get("soc_analysis_data")
    if not alert_data:
        st.error("❌ No alert data found. Please run AI analysis first.")
        return

    # Verify triaging data is uploaded
    excel_data = st.session_state.get("predictions_excel_data")
    excel_filename = st.session_state.get("predictions_excel_filename")

    if not excel_data:
        st.error("❌ No triaging data found. Please complete triaging first.")
        return

    # Initialize API client
    final_api_key = os.getenv("GOOGLE_API_KEY")
    predictions_api_url = os.getenv("PREDICTIONS_API_URL", "http://localhost:8000")

    try:
        client = get_predictions_client(predictions_api_url, final_api_key)

        # Enhanced upload status
        if not st.session_state.get("predictions_uploaded"):
            st.markdown(
                """
                <div style="background: #e0e7ff; border: 2px solid #6366f1; 
                           border-radius: 8px; padding: 1rem; margin: 1rem 0;">
                    <h3 style="color: #6366f1; margin: 0;">📤 Uploading Investigation Template</h3>
                </div>
                """,
                unsafe_allow_html=True
            )

            with st.spinner("Uploading investigation data..."):
                upload_success = _upload_to_predictions_api(excel_data, excel_filename)

            if upload_success:
                st.success("✅ Template uploaded successfully!")
                st.session_state.predictions_uploaded = True
            else:
                st.error(
                    f"❌ Upload failed: {st.session_state.get('predictions_upload_error', 'Unknown error')}"
                )
                return
        else:
            st.success("✅ Template already uploaded to predictions API")

        # Verify upload with enhanced display
        preview_result = client.get_upload_preview()
        if preview_result.get("success"):
            st.success(
                f"✅ Data verified: {preview_result.get('total_rows', 0)} investigation steps loaded"
            )

        st.markdown("---")

        # Check testing mode
        testing_mode = os.getenv("TESTING")

        # Extract entities
        entities = alert_data.get("entities", {})
        entities_list = (
            entities.get("entities", [])
            if isinstance(entities, dict)
            else (entities if isinstance(entities, list) else [])
        )

        # Separate Account and IP entities
        account_entities = [e for e in entities_list if e.get("kind") == "Account"]
        ip_entities = [e for e in entities_list if e.get("kind") == "Ip"]

        # Enhanced entity summary
        if account_entities or ip_entities:
            st.markdown(
                """
                <div style="background: #f8fafc; border: 2px solid #e2e8f0; 
                           border-radius: 8px; padding: 1rem; margin: 1rem 0;">
                    <h3 style="color: #374151; margin: 0; text-align: center;">
                        📊 Entity Analysis Overview
                    </h3>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            col1, col2 = st.columns(2)
            with col1:
                if account_entities:
                    st.metric("👤 Account Entities", len(account_entities))
            with col2:
                if ip_entities:
                    st.metric("🌐 IP Entities", len(ip_entities))

        # Conditional display based on testing mode
        if testing_mode:
            # Testing mode: Show account analysis directly
            if account_entities:
                st.markdown(f"### 👤 Analyzing {len(account_entities)} Account(s)")
                analyze_entities_parallel_enhanced(account_entities, client)
            else:
                st.warning("⚠️ No account entities found in this alert")

        else:
            # Production mode: Show tabs
            tab_list = ["📊 Summary"]
            if account_entities:
                tab_list.append("👤 Account Analysis")
            if ip_entities:
                tab_list.append("🌐 IP Analysis")

            tabs = st.tabs(tab_list)

            # Summary tab
            with tabs[0]:
                st.markdown("### 📊 Analysis Overview")
                
                if account_entities or ip_entities:
                    col1, col2 = st.columns(2)
                    with col1:
                        if account_entities:
                            st.metric("👤 Account Entities", len(account_entities))
                    with col2:
                        if ip_entities:
                            st.metric("🌐 IP Entities", len(ip_entities))
                    
                    st.info("🤖 Use the tabs above to analyze specific entity types")
                else:
                    st.warning("⚠️ No entities found in this alert for analysis")

            # Account analysis tab
            if account_entities and len(tabs) > 1:
                with tabs[1]:
                    st.markdown(f"### 👤 Analyzing {len(account_entities)} Account(s)")
                    analyze_entities_parallel_enhanced(account_entities, client)

            # IP analysis tab
            if ip_entities:
                ip_tab_index = 2 if account_entities else 1
                if len(tabs) > ip_tab_index:
                    with tabs[ip_tab_index]:
                        st.markdown(
                            f"### 🌐 Analyzing {len(ip_entities)} IP Address(es)"
                        )
                        st.info("🤖 Running parallel analysis for all IPs...")
                        analyze_ip_entities_parallel(ip_entities, client)

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        with st.expander("View Full Error"):
            st.code(traceback.format_exc())


# Main function to replace the original predictions page
def display_predictions_tab_enhanced():
    """Main function to display enhanced predictions tab"""
    display_enhanced_predictions_tab()