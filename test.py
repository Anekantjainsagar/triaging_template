import os
from dotenv import load_dotenv
from routes.src.enhanced_kql_generator import EnhancedKQLGenerator

load_dotenv()

print("🔍 Checking Configuration...\n")

# Check Serper
serper = os.getenv("SERPER_API_KEY")
print(f"✅ Serper API: {'Configured' if serper else '❌ Missing'}")

# Check Gemini
gemini = os.getenv("GOOGLE_API_KEY")
print(f"✅ Gemini API: {'Configured' if gemini else '⚠️ Missing (will use Ollama)'}")

# Check Ollama
ollama = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
print(f"✅ Ollama Model: {ollama}")

# Test KQL Generator
print("\n🧪 Testing KQL Generator...")
try:
    generator = EnhancedKQLGenerator()
    print("✅ KQL Generator initialized successfully")

    # Test query generation
    kql, explanation = generator.generate_kql_query(
        step_name="Verify User Sign-in Activity",
        explanation="Check user authentication logs for suspicious activity",
        step_number=1,
        rule_context="User authentication investigation",
    )

    if kql:
        print(f"✅ Generated KQL query ({len(kql)} characters)")
        print(f"✅ Explanation: {explanation[:100]}...")
    else:
        print("⚠️ No KQL generated (may be normal for some steps)")

except Exception as e:
    print(f"❌ Error: {str(e)}")

print("\n✅ Setup verification complete!")
