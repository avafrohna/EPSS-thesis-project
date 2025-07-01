import os
import re
import csv
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

today = datetime.now(timezone.utc).date()
days_back = 100
date = today - timedelta(days=days_back)
output_file = "hackernews_cve_cleaned.csv"
collected = []

BASE_URL = "https://hacker-news.firebaseio.com/v0"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def is_within_time(unix_time):
    dt = datetime.fromtimestamp(unix_time, tz=timezone.utc).date()
    return days_back <= dt <= today

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

max_id = get_max_item_id()
ids_to_check = range(max_id, max_id - 500000, -1)

with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(fetch_item, i): i for i in ids_to_check}

    for future in as_completed(futures):
        item = future.result()
        if not item or item.get("type") != "story" or item.get("dead") or item.get("deleted"):
            continue

        post_time = item.get("time")
        if not post_time or not is_within_time(post_time):
            continue

        content = f"{item.get('title', '')} {item.get('text', '')}"
        if item.get("url"):
            try:
                response = requests.get(item["url"], timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")
                linked_text = soup.get_text()
                item["linked_text"] = linked_text
                content += " " + linked_text
            except:
                pass
        cves = CVE_PATTERN.findall(content)
        if not cves:
            continue

        info = extract_info(item)
        combined_text = clean_text(f"{info['title']} {info['text']}")
        for cve in set(cves):
            collected.append({
                "cve": cve,
                "timestamp": info["date"],
                "source": "hacker news",
                "text": combined_text
            })

file_exists = os.path.exists(output_file)

with open(output_file, "a", newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=["cve", "timestamp", "source", "text"])
    if not file_exists:
        writer.writeheader()
    writer.writerows(collected)