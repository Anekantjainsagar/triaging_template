import json
import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=api_key)


def load_json(json_file_path):
    if not os.path.exists(json_file_path):
        print(f"File not found: {json_file_path}")
        return None
    with open(json_file_path, "r") as file:
        content = file.read()
        if not content.strip():
            print(f"File is empty: {json_file_path}")
            return None
        return json.loads(content)


def generate_correlation_report(log_data):
    # Initialize Gemini model (adjust model name as per your environment)
    model = genai.GenerativeModel("gemini-2.5-flash")

    # Build prompt for correlation analysis - you may customize based on exact task
    prompt = f"Analyze and correlate the following log analytics data:\n{json.dumps(log_data, indent=2)}"

    # Generate correlated text response from Gemini
    response = model.generate_content(prompt)
    return response.text


def save_to_markdown(filename, content):
    with open(filename, "w") as md_file:
        md_file.write(content)


if __name__ == "__main__":
    json_path = (
        "sentinel_user_data_20251107_0500_0700.json"  # Input JSON file path
    )
    md_output_path = "correlation_report.md"  # Output markdown file

    log_analytics_json = load_json(json_path)
    correlation_text = generate_correlation_report(log_analytics_json)
    save_to_markdown(md_output_path, correlation_text)

    print(f"Correlation report saved to {md_output_path}")
