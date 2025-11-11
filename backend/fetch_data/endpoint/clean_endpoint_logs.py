import json
import os
from datetime import datetime
from typing import Dict, List, Optional


def clean_endpoint_security_file(input_file_path: str, output_path: str = None) -> str:
    """
    Clean a single endpoint security data file

    Args:
        input_file_path: Path to the input JSON file
        output_path: Optional output path (auto-generated if None)

    Returns:
        Path to cleaned file, or None if failed
    """

    if not os.path.exists(input_file_path):
        print(f"❌ File not found: {input_file_path}")
        return None

    try:
        # Load the original JSON data
        with open(input_file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        print(f"\n{'='*60}")
        print(f"🔒 Cleaning Endpoint Security: {os.path.basename(input_file_path)}")
        print(f"{'='*60}")

        # Define columns to remove from endpoint security tables
        endpoint_columns_to_remove = [
            "TenantId",
            "SourceSystem",
            "ResourceId",
            "MG",
            "ManagementGroupName",
            "Type",
            "_ResourceId",
            "SubscriptionId",
            "Task",
            "ReportId",
        ]

        cleaned_data = {}
        total_original_records = 0
        total_cleaned_records = 0

        # Process each endpoint security table
        for table_name, table_data in data.items():
            if not isinstance(table_data, list):
                print(f"⚠️  Skipping {table_name}: Not a list")
                cleaned_data[table_name] = table_data
                continue

            print(f"📊 Processing {table_name}: {len(table_data)} records")
            total_original_records += len(table_data)

            cleaned_table = []
            for record in table_data:
                # Remove specified columns
                cleaned_record = {
                    k: v
                    for k, v in record.items()
                    if k not in endpoint_columns_to_remove
                }
                cleaned_table.append(cleaned_record)
                total_cleaned_records += 1

            cleaned_data[table_name] = cleaned_table
            print(f"   ✅ Cleaned {table_name}: {len(cleaned_table)} records")

        # Generate output filename if not provided
        if output_path is None:
            input_dir = os.path.dirname(input_file_path)
            input_filename = os.path.basename(input_file_path)
            output_filename = f"cleaned_{input_filename}"
            output_file_path = os.path.join(input_dir, output_filename)
        else:
            output_file_path = (
                output_path  # Add this line to handle when output_path is provided
            )

        # Save cleaned data
        with open(output_file_path, "w", encoding="utf-8") as file:
            json.dump(cleaned_data, file, indent=2, ensure_ascii=False)

        print(f"\n✅ Cleaned endpoint security data saved to: {output_file_path}")

        # Show statistics
        original_size = os.path.getsize(input_file_path)
        cleaned_size = os.path.getsize(output_file_path)
        reduction = ((original_size - cleaned_size) / original_size) * 100

        print(f"\n📦 Size comparison:")
        print(f"   Original: {original_size:,} bytes")
        print(f"   Cleaned:  {cleaned_size:,} bytes")
        print(f"   Reduction: {reduction:.1f}%")
        print(f"   Total records processed: {total_cleaned_records}")
        print(f"{'='*60}\n")

        return output_file_path

    except Exception as e:
        print(f"❌ Error processing file: {e}")
        import traceback

        traceback.print_exc()
        return None


def clean_single_endpoint_file():
    """
    Clean a single endpoint security file directly
    """
    print("\n" + "=" * 60)
    print("🔒 Single Endpoint Security File Cleaner")
    print("=" * 60)

    # Use the file from your directory
    input_file = "sentinel_logs1/sentinel_logs_2025-11-07 06-00-07-00/sentinel_endpoint_security_20251107_0600_0700.json"

    if os.path.exists(input_file):
        print(f"📄 Processing: {input_file}\n")
        output_file = clean_endpoint_security_file(input_file)

        if output_file:
            print(f"\n✅ Success! Cleaned file: {output_file}")
        else:
            print("\n❌ Cleaning failed")
    else:
        print(f"❌ File not found: {input_file}")
        print("\nAvailable files in current directory:")
        for root, dirs, files in os.walk("."):
            for file in files:
                if "endpoint_security" in file and file.endswith(".json"):
                    print(f"  - {os.path.join(root, file)}")


def main():
    """
    Main function with menu options
    """
    print("\n" + "=" * 60)
    print("🔒 Endpoint Security Cleaning Options")
    print("=" * 60)
    print("1. Clean single endpoint security file")
    print("2. Use selective workflow (recommended)")
    print("3. Exit")

    choice = input("\nChoose option (1-3): ").strip()

    if choice == "1":
        clean_single_endpoint_file()
    elif choice == "2":
        print("\n🎯 Run the selective workflow instead:")
        print("   python selective_workflow.py")
    elif choice == "3":
        print("Exiting...")
    else:
        print("Invalid choice. Please run again.")


if __name__ == "__main__":
    main()
