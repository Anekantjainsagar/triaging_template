import os
import time
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Get all API keys
api_keys = [
    os.getenv("GOOGLE_API_KEY_1", os.getenv("GOOGLE_API_KEY")),
    os.getenv("GOOGLE_API_KEY_2"),
    os.getenv("GOOGLE_API_KEY_3"),
    os.getenv("GOOGLE_API_KEY_4"),
    os.getenv("GOOGLE_API_KEY_5"),
    os.getenv("GOOGLE_API_KEY_6"),
    os.getenv("GOOGLE_API_KEY_7"),
]

# Filter out None values
api_keys = [key for key in api_keys if key]

print(f"Testing {len(api_keys)} API keys...")
print("=" * 50)

for i, key in enumerate(api_keys, 1):
    try:
        genai.configure(api_key=key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        response = model.generate_content("Say 'OK' if you can respond")
        
        if response and response.text:
            print(f"[OK] Key {i}: Working - {response.text.strip()}")
        else:
            print(f"[FAIL] Key {i}: No response")
            
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "quota" in error_msg.lower():
            print(f"[QUOTA] Key {i}: Quota exceeded")
        elif "503" in error_msg or "overloaded" in error_msg.lower():
            print(f"[OVERLOAD] Key {i}: Service overloaded")
        else:
            print(f"[ERROR] Key {i}: {error_msg[:100]}")
    
    time.sleep(1)  # Brief pause between tests