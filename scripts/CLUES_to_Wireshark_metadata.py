import json
import csv
import os

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, '..', 'data')
    output_file = os.path.join(script_dir, '..', 'bluetooth_uuids')

    # Precedence order: human-verified beats APK-search beats web-search.
    # First-occurrence wins during dedup, so list highest-trust sources first.
    input_files = [
        os.path.join(data_dir, 'CLUES_data_human_verified.json'),
        os.path.join(data_dir, 'CLUES_data_LLM_Android_APK_search.json'),
        os.path.join(data_dir, 'CLUES_data_LLM_web_search.json'),
    ]

    seen_uuids = set()
    rows = []

    for input_file in input_files:
        try:
            with open(input_file, "r") as f:
                clues_data = json.load(f)
        except Exception as e:
            print(f"Error reading '{input_file}': {e}")
            continue

        for entry in clues_data:
            if "regex" in entry.keys():
                continue

            first_field = entry.get("UUID")
            if not first_field:
                continue

            if first_field in seen_uuids:
                continue
            seen_uuids.add(first_field)

            company = entry.get("company", "Unknown")
            if "UUID_name" in entry:
                second_field = f"{company}__{entry['UUID_name']}"
            else:
                second_field = f"{company}__{entry['UUID_purpose']}"

            rows.append([first_field, second_field])

    try:
        with open(output_file, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            for row in rows:
                csv_writer.writerow(row)

        print(f"CSV file '{output_file}' created successfully.")
        print(f"Merged {len(rows)} UUIDs from {len(input_files)} input file(s).")
        print(f"You must copy it to the correct location for Wireshark based on your OS.")
        print(f"E.g. on Linux and macOS: ~/.config/wireshark/bluetooth_uuids")
        print(r"E.g. on Windows: C:\Users\username\AppData\Roaming\Wireshark\bluetooth_uuids")

    except Exception as e:
        print(f"Error writing '{output_file}': {e}")

if __name__ == "__main__":
    main()
