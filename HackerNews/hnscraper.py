import requests
import time
from datetime import datetime, timezone, date

BASE_URL = "https://hacker-news.firebaseio.com/v0"

def get_item(item_id):
    url = f"{BASE_URL}/item/{item_id}.json"
    resp = requests.get(url)
    return resp.json()

def get_latest_story_ids(limit=100):
    url = f"{BASE_URL}/newstories.json"
    resp = requests.get(url)
    return resp.json()[:limit]

def is_today(unix_time):
    dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    return dt.date() == date.today()

def get_stories_from_today(limit):
    stories = []
    ids = get_latest_story_ids(limit)
    for item_id in ids:
        item = get_item(item_id)
        if item and 'time' in item and is_today(item['time']):
            stories.append(item)
        time.sleep(0.5)
    return stories

if __name__ == "__main__":
    stories_today = get_stories_from_today(limit=1500)

    cve_stories_today = []
    for item in stories_today:
        title = item.get("title", "")
        text = item.get("text", "")
        content = f"{title} {text}"
        if "CVE" in content:
            cve_stories_today.append(item)

    cve_stories_today.sort(key=lambda x: x['time'], reverse=True)

    print(f"\n🛡️ Hacker News posts from today mentioning 'CVE' ({date.today()}):\n")

    if cve_stories_today:
        for item in cve_stories_today:
            title = item.get("title", "(no title)")
            item_id = item["id"]
            timestamp = datetime.fromtimestamp(item["time"], tz=timezone.utc).isoformat()
            print(f"🆔 ID: {item_id}")
            print(f"🕒 Posted: {timestamp}")
            print(f"📌 Title: {title}\n")
        print(f"✅ Total posts mentioning 'CVE': {len(cve_stories_today)}")
    else:
        print("⚠️ No posts mentioning 'CVE' found today.")