import requests
import re
import time
from datetime import datetime, timezone, date

BASE_URL = "https://hacker-news.firebaseio.com/v0"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def get_item(item_id):
    url = f"{BASE_URL}/item/{item_id}.json"
    resp = requests.get(url)
    return resp.json()

def get_latest_story_ids(limit=100):
    url = f"{BASE_URL}/newstories.json"
    resp = requests.get(url)
    return resp.json()[:limit]

def extract_cve_mentions(text):
    return CVE_PATTERN.findall(text or "")

def is_today(unix_time):
    dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    return dt.date() == date.today()

def scrape_recent_stories(limit=100):
    stories = []
    ids = get_latest_story_ids(limit)
    for item_id in ids:
        item = get_item(item_id)
        if item and 'text' in item:
            cves = extract_cve_mentions(item['title'] + " " + item['text'])
            if cves:
                stories.append({
                    "id": item_id,
                    "title": item.get("title", ""),
                    "text": item.get("text", ""),
                    "cves": cves,
                    "time": item.get("time"),
                    "score": item.get("score", 0),
                    "type": item.get("type"),
                    "descendants": item.get("descendants", 0)
                })
        time.sleep(0.5)
    return stories

def get_stories_from_today(limit=500):
    stories = []
    ids = get_latest_story_ids(limit)
    for item_id in ids:
        item = get_item(item_id)
        if item and 'time' in item and is_today(item['time']):
            stories.append(item)
        time.sleep(0.5)
    return stories

if __name__ == "__main__":
    stories_today = get_stories_from_today(limit=500)

    stories_today.sort(key=lambda x: x['time'], reverse=True)

    print(f"\n🗓️ Hacker News posts from today ({date.today()}):\n")

    if stories_today:
        storycount = 0
        for item in stories_today:
            title = item.get("title", "(no title)")
            item_id = item["id"]
            print(f"🆔 ID: {item_id}")
            print(f"📌 Title: {title}")
            storycount += 1
        print({storycount})
    else:
        print("No posts found for today.")