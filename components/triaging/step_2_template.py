import streamlit as st
import time
import os
from src.template_parser import TemplateParser
from src.web_llm_enhancer import WebLLMEnhancer
from src.template_generator import EnhancedTemplateGenerator


def render_step_2():
    st.markdown(
        '<div class="step-header"><h2>Step 3: Template Enhancement & Generation</h2></div>',
        unsafe_allow_html=True,
    )
    
    rule_number = st.session_state.selected_alert.get("rule")

    # Process template enhancement
    process_template_enhancement(rule_number)


def process_template_enhancement(rule_number):
    progress_bar = st.progress(0, text="Initializing...")
    status_text = st.empty()

    try:
        # Step 1: Find and parse template
        status_text.text("🔍 Searching for triaging template...")
        progress_bar.progress(20, text="Searching for template...")

        original_steps = find_and_parse_template(rule_number)
        if not original_steps:
            return

        # Step 2: Enhance template
        status_text.text("🛠️ Enhancing template...")
        progress_bar.progress(60, text="Enhancing with validation...")

        enhanced_steps, validation_report = enhance_template(
            rule_number, original_steps
        )

        # Step 3: Generate Excel template
        status_text.text("📊 Generating Excel template...")
        progress_bar.progress(80, text="Generating Excel...")

        excel_data = generate_excel_template(rule_number, enhanced_steps)

        # Store results
        st.session_state.original_steps = original_steps
        st.session_state.enhanced_steps = enhanced_steps
        st.session_state.validation_report = validation_report
        st.session_state.excel_template_data = excel_data

        progress_bar.progress(100, text="✅ Complete!")
        status_text.text("✅ Template generation complete!")

        # Display results
        display_enhancement_results(
            rule_number, original_steps, enhanced_steps, validation_report
        )

    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ Error: {str(e)}")
        if st.button("← Go Back"):
            st.session_state.step = 1
            st.rerun()


def find_and_parse_template(rule_number):
    parser = TemplateParser()
    template_dir = "data/triaging_templates"

    if not os.path.exists(template_dir):
        st.warning(f"⚠️ Template directory not found: {template_dir}")
        return None

    # Find matching template file
    template_path = find_template_file(template_dir, rule_number)
    if not template_path:
        return None

    # Parse template
    if template_path.endswith(".csv"):
        return parser.parse_csv_template(template_path)
    else:
        return parser.parse_excel_template(template_path)


def find_template_file(template_dir, rule_number):
    import re
    import os

    rule_num_match = re.search(r"#?(\d+)", rule_number)
    rule_num = (
        rule_num_match.group(1)
        if rule_num_match
        else rule_number.replace("#", "").strip()
    )

    all_files = os.listdir(template_dir)
    template_files = [
        f
        for f in all_files
        if rule_num in f and (f.endswith(".csv") or f.endswith(".xlsx"))
    ]

    if not template_files:
        st.error(f"❌ No template found for {rule_number}")
        return None

    return os.path.join(template_dir, template_files[0])


def enhance_template(rule_number, original_steps):
    enhancer = WebLLMEnhancer()
    start_time = time.time()

    enhanced_steps = enhancer.enhance_template_steps(
        rule_number=rule_number,
        original_steps=original_steps,
    )

    validation_report = enhancer.validate_enhanced_steps(original_steps, enhanced_steps)

    return enhanced_steps, validation_report


def generate_excel_template(rule_number, enhanced_steps):
    template_gen = EnhancedTemplateGenerator()
    template_df = template_gen.generate_clean_template(
        rule_number=rule_number, enhanced_steps=enhanced_steps
    )
    return template_gen.export_to_excel(template_df, rule_number)


def display_enhancement_results(
    rule_number, original_steps, enhanced_steps, validation_report
):
    # This would contain the detailed display logic from the original code
    # Simplified for brevity
    st.success(f"✅ Enhanced and validated {len(enhanced_steps)} steps")

    # Display tabs for different views
    tab1, tab2, tab3 = st.tabs(["Excel Preview", "Before/After", "Validation"])

    with tab1:
        st.dataframe(st.session_state.excel_template_data)

    with tab2:
        display_comparison(original_steps, enhanced_steps)

    with tab3:
        display_validation_report(validation_report)


def display_comparison(original_steps, enhanced_steps):
    for i, (orig, enh) in enumerate(zip(original_steps, enhanced_steps)):
        with st.expander(f"Step {i+1}: {orig.get('step_name')}"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Original**")
                st.text_area(
                    "Explanation", value=orig.get("explanation"), disabled=True
                )
            with col2:
                st.markdown("**Enhanced**")
                st.text_area("Explanation", value=enh.get("explanation"), disabled=True)


def display_validation_report(validation_report):
    st.metric("Names Preserved", f"{validation_report.get('names_preserved', 0)}")
    st.metric(
        "Explanations Improved", f"{validation_report.get('explanations_improved', 0)}"
    )

    if validation_report.get("issues"):
        st.warning("Validation issues found")
        for issue in validation_report["issues"]:
            st.error(issue)
