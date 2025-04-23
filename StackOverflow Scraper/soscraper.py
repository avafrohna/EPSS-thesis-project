import requests
import json
import re
import os
from datetime import datetime, timedelta

def extract_cves(text):
    return re.findall(r'CVE-\d{4}-\d{4,7}', text)

# Define the date range for April 19, 2025
from_date = int(datetime(2025, 4, 10).timestamp())
to_date = int((datetime(2025, 4, 10) + timedelta(days=1)).timestamp())

url = "https://api.stackexchange.com/2.3/questions"

params = {
    "fromdate": from_date,
    "todate": to_date,
    "order": "desc",
    "sort": "creation",
    "site": "stackoverflow",
    "pagesize": 100,
    "filter": "withbody"  # Include full body content
}

results = []
has_more = True
page = 1

while has_more:
    print(f"🔎 Fetching page {page}")
    params["page"] = page
    response = requests.get(url, params=params)
    data = response.json()

    for item in data.get("items", []):
        title = item.get("title", "")
        body = item.get("body", "")
        link = item.get("link", "")

        found_cves = extract_cves(title + " " + body)
        if not found_cves:
            continue

        cve_counts = {cve: 1 for cve in found_cves}

        results.append({
            "cves": found_cves,
            "cve_counts": cve_counts,
            "title": title,
            "permalink": link,
            "text": body,
            "comments": []
        })

    has_more = data.get("has_more", False)
    page += 1

# Load existing data if file exists
json_file = "stackoverflow_scraper.json"
if os.path.exists(json_file):
    with open(json_file, "r") as f:
        try:
            existing_data = json.load(f)
        except json.JSONDecodeError:
            existing_data = []
else:
    existing_data = []

# Prevent duplicates using permalinks
existing_links = {entry["permalink"] for entry in existing_data}
new_entries = [entry for entry in results if entry["permalink"] not in existing_links]

if new_entries:
    combined_data = existing_data + new_entries
    with open(json_file, "w") as f:
        json.dump(combined_data, f, indent=2)
    print(f"✅ Added {len(new_entries)} new CVE entries to {json_file}")
else:
    print("❌ No new CVEs found.")