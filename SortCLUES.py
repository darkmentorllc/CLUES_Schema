# Sorting logic auto-generated via AI, and results just eyeballed to see that they look good enough. Most likely has issues
# The basic goal is to sort first by company name, alphabetically, ascending order
# Then second to group things so that UUIDs with parent_UUID fields are placed underneath the parent_UUIDs
# and the placed-under elements should be sorted also in ascending order.

import json
from itertools import groupby
from collections import defaultdict

def merge_entries(entry1, entry2):
    merged_entry = {}
    for key in entry1:
        if isinstance(entry1[key], list) and isinstance(entry2[key], list):
            merged_entry[key] = list({json.dumps(item) for item in entry1[key] + entry2[key]})
            merged_entry[key] = [json.loads(item) for item in merged_entry[key]]
        elif isinstance(entry1[key], str) and isinstance(entry2[key], str):
            if entry1[key] == entry2[key]:
                merged_entry[key] = entry1[key]
            else:
                merged_entry[key] = f"MERGED: ({entry1[key]}), ({entry2[key]})"
        else:
            merged_entry[key] = entry1[key] if entry1[key] is not None else entry2[key]
    return merged_entry

def entries_are_equal(entry1, entry2):
    if not entry1 or not entry2:
        return False
    return all(entry1.get(key) == entry2.get(key) for key in entry1)

def sort_custom_uuids(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    def sort_key(entry):
        company = entry['company'] if entry['company'] is not None else ''
        return company, entry['UUID_purpose'], entry['UUID']

    # Convert UUID and parent_UUID to lowercase and group entries by UUID
    uuid_groups = {}
    for entry in data:
        entry['UUID'] = entry['UUID'].lower()
        if 'parent_UUID' in entry:
            entry['parent_UUID'] = entry['parent_UUID'].lower()
        uuid = entry['UUID']
        if uuid in uuid_groups:
            uuid_groups[uuid] = merge_entries(uuid_groups[uuid], entry)
        else:
            uuid_groups[uuid] = entry

    # Create company groups with parent-child relationships
    company_groups = defaultdict(lambda: {'services': [], 'orphan_chars': [], 'orphans': []})
    for entry in uuid_groups.values():
        company = entry['company'] if entry['company'] is not None else ''
        if "GATT Service" in entry['UUID_usage_array']:
            company_groups[company]['services'].append(entry)
        elif "GATT Characteristic" in entry['UUID_usage_array']:
            if 'parent_UUID' in entry:
                if entry['parent_UUID'] in uuid_groups:
                    company_groups[company].setdefault(entry['parent_UUID'], []).append(entry)
                else:
                    company_groups[company]['orphans'].append(entry)
            else:
                company_groups[company]['orphan_chars'].append(entry)

    result = []
    seen_uuids = set()

    # Sort companies and process each group
    for company, group in sorted(company_groups.items()):
        services = sorted(group['services'], key=lambda x: x['UUID'])
        for service in services:
            if service['UUID'] not in seen_uuids:
                result.append(service)
                seen_uuids.add(service['UUID'])

            # Add related characteristics
            related_characteristics = sorted(group.get(service['UUID'], []), key=lambda x: x['UUID'])
            for char in related_characteristics:
                if char['UUID'] not in seen_uuids:
                    result.append(char)
                    seen_uuids.add(char['UUID'])

        # Add orphan characteristics
        orphan_chars = sorted(group['orphan_chars'], key=lambda x: x['UUID'])
        for char in orphan_chars:
            if char['UUID'] not in seen_uuids:
                result.append(char)
                seen_uuids.add(char['UUID'])

        # Add orphaned entries whose parent_UUID was not found
        orphans = sorted(group['orphans'], key=lambda x: x['UUID'])
        for orphan in orphans:
            if orphan['UUID'] not in seen_uuids:
                result.append(orphan)
                seen_uuids.add(orphan['UUID'])

    with open(file_path, 'w') as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    sort_custom_uuids('CLUES_data.json')
