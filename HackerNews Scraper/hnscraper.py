import requests
from bs4 import BeautifulSoup
import csv
import os
import re
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

today = datetime.now(timezone.utc).date()
one_week_ago = today - timedelta(days=100)
output_file = "hackernews_cve_cleaned.csv"
collected = []

BASE_URL = "https://hacker-news.firebaseio.com/v0"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def is_within_last_week(unix_time):
    dt = datetime.fromtimestamp(unix_time, tz=timezone.utc).date()
    return one_week_ago <= dt <= today

def fetch_item(item_id):
    url = f"{BASE_URL}/item/{item_id}.json"
    try:
        resp = requests.get(url)
        return resp.json()
    except:
        return None
    
def get_max_item_id():
    resp = requests.get(f"{BASE_URL}/maxitem.json")
    return resp.json()

def extract_info(item):
    return {
        "id": item.get("id"),
        "title": item.get("title", ""),
        "text": item.get("linked_text", item.get("text", "")),
        "date": datetime.fromtimestamp(item.get("time", 0), tz=timezone.utc).strftime("%Y-%m-%d"),
        "url": f"https://news.ycombinator.com/item?id={item.get('id')}"
    }

def clean_text(text):
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

print(f"Fetching Hacker News posts from {one_week_ago} to {today}...")
max_id = get_max_item_id()

ids_to_check = range(max_id, max_id - 100000, -1)

with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(fetch_item, i): i for i in ids_to_check}

    for count, future in enumerate(as_completed(futures)):
        if count % 10 == 0:
            print(f"🔄 Checked {count} posts...")

        item = future.result()
        if not item or item.get("type") != "story" or item.get("dead") or item.get("deleted"):
            continue

        post_time = item.get("time")
        if not post_time or not is_within_last_week(post_time):
            continue

        content = f"{item.get('title', '')} {item.get('text', '')}"
        linked_url = item.get("url")
        if linked_url:
            try:
                response = requests.get(linked_url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")
                linked_text = soup.get_text()
                item['linked_text'] = linked_text
                content += " " + linked_text
            except:
                pass
        cves = CVE_PATTERN.findall(content)
        if not cves:
            continue
        else:
            print(f"🔎 Found CVEs in post {item.get('id')}: {set(cves)}")

        info = extract_info(item)
        collected.append((cves, info))

print(f"\n🧮 Finished scanning. Total posts checked: {max_id - (max_id - 100000)}")
print(f"\n✅ Collected {len(collected)} posts from {one_week_ago} to {today} mentioning CVEs.\n")

file_exists = os.path.exists(output_file)

with open(output_file, "a", newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=["cve", "timestamp", "source", "text"])

    if not file_exists:
        writer.writeheader()
    
    for cves, info in collected:
        for cve in set(cves):
            if not re.match(r'CVE-\d{4}-\d{4,7}', cve):
                continue

            writer.writerow({
                "cve": cve,
                "timestamp": info["date"],
                "source": "hacker news",
                "text": clean_text(f"{info['title']} {info['text']}")
            })

print(f"✅ CSV file updated with {sum(len(set(cves)) for cves, _ in collected)} CVE entries from the last week.")