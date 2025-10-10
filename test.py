import pandas as pd

# Read your template
template_path = "data/triaging_templates/Rule#183 01-Jul'25 (208306)(Sheet1).csv"

# Try different encodings
df = None
for encoding in ["utf-8", "latin1", "cp1252"]:
    try:
        df = pd.read_csv(template_path, encoding=encoding)
        print(f"✅ Successfully read with {encoding}")
        break
    except:
        continue

if df is None:
    print("❌ Could not read CSV")
else:
    print("\n" + "=" * 80)
    print("COLUMN NAMES IN YOUR TEMPLATE:")
    print("=" * 80)
    for i, col in enumerate(df.columns, 1):
        print(f"{i}. '{col}'")

    print("\n" + "=" * 80)
    print("FIRST 5 ROWS OF DATA:")
    print("=" * 80)
    print(df.head(5).to_string())

    print("\n" + "=" * 80)
    print("CHECKING 'Name' COLUMN (Step Names):")
    print("=" * 80)

    if "Name" in df.columns:
        for idx, row in df.iterrows():
            name = str(row.get("Name", "")).strip()
            explanation = str(row.get("Explanation", "")).strip()

            if name and name != "nan" and len(name) > 2:
                print(f"\nRow {idx}: {name}")
                print(f"  Explanation: {explanation[:60]}...")
    else:
        print("❌ 'Name' column not found!")
        print(f"Available columns: {list(df.columns)}")
