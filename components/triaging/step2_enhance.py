# step2_enhance.py - UPDATED WITH KQL EXECUTION
import streamlit as st
from io import BytesIO


def contains_ip_not_vip(text):
    """Check if text contains 'ip' but not as part of 'vip'"""
    if "ip" not in text:
        return False
    import re

    ip_patterns = [
        r"\bip\b",
        r"ip\s+address",
        r"ip\s+reputation",
        r"source\s+ip",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in ip_patterns)


def _upload_to_predictions_api(excel_data: bytes, filename: str):
    """Upload Excel file to predictions API immediately"""
    try:
        import os
        from api_client.predictions_api_client import get_predictions_client

        # Use first available API key from the multi-key system
        api_keys = [
            os.getenv("GOOGLE_API_KEY_1", os.getenv("GOOGLE_API_KEY")),
            os.getenv("GOOGLE_API_KEY_2"),
            os.getenv("GOOGLE_API_KEY_3"),
            os.getenv("GOOGLE_API_KEY_4"),
            os.getenv("GOOGLE_API_KEY_5"),
            os.getenv("GOOGLE_API_KEY_6"),
            os.getenv("GOOGLE_API_KEY_7"),
        ]
        api_keys = [key for key in api_keys if key]  # Filter out None values
        final_api_key = api_keys[0] if api_keys else os.getenv("GOOGLE_API_KEY")
        predictions_api_url = os.getenv(
            "PREDICTIONS_API_URL", "http://localhost:8000/predictions"
        )

        client = get_predictions_client(predictions_api_url, final_api_key)

        file_obj = BytesIO(excel_data)

        with st.spinner("📤 Uploading to predictions API..."):
            upload_result = client.upload_excel_bytes(file_obj, filename)

        if upload_result.get("success"):
            st.session_state.predictions_uploaded = True
            st.session_state.predictions_upload_result = upload_result
            st.session_state.predictions_file_data = excel_data
            st.session_state.predictions_filename = filename
            print(f"✅ Successfully uploaded {upload_result.get('total_rows', 0)} rows")
            return True
        else:
            st.session_state.predictions_upload_error = upload_result.get(
                "error", "Unknown error"
            )
            print(f"❌ Upload failed: {upload_result.get('error')}")
            return False

    except Exception as e:
        st.session_state.predictions_upload_error = str(e)
        print(f"❌ Upload exception: {str(e)}")
        return False

