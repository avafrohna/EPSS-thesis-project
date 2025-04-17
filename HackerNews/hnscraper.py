import requests
import time
import re
import json
from datetime import datetime, timezone, date, timedelta
from sentence_transformers import SentenceTransformer

BASE_URL = "https://hacker-news.firebaseio.com/v0"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

model = SentenceTransformer("all-MiniLM-L6-v2")

def get_item(item_id):
    url = f"{BASE_URL}/item/{item_id}.json"
    resp = requests.get(url)
    return resp.json()

def get_latest_story_ids(limit):
    url = f"{BASE_URL}/newstories.json"
    resp = requests.get(url)
    return resp.json()[:limit]

def get_comments(comment_ids):
    comments = []
    if not comment_ids:
        return comments
    for cid in comment_ids:
        comment = get_item(cid)
        if comment and 'text' in comment:
            comments.append(comment['text'])
        time.sleep(0.2)
    return comments

def is_recent(unix_time):
    post_dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    return (now_utc - post_dt) <= timedelta(days=2)

def get_recent_story_ids(max_count=2000):
    max_item_url = f"{BASE_URL}/maxitem.json"
    max_id = requests.get(max_item_url).json()
    story_ids = []
    checked = 0
    current_id = max_id
    MAX_LOOKUPS = 3000

    while current_id > 0 and checked < MAX_LOOKUPS:
        item = get_item(current_id)
        checked += 1

        if item and item.get("type") == "story":
            post_time = item.get("time")
            if post_time and is_recent(post_time):
                if item.get("dead") or item.get("deleted"):
                    current_id -= 1
                    continue

                title = item.get("title", "").strip()
                if not title:
                    current_id -= 1
                    continue

                text = item.get("text", "")
                content = f"{title} {text}"
                cves = CVE_PATTERN.findall(content)

                display_title = title[:60]
                post_num = len(story_ids) + 1

                if cves:
                    print(f"✅ Post {post_num}: '{display_title}' contains CVEs: {cves}")
                else:
                    print(f"❌ Post {post_num}: '{display_title}' has no CVE.")

                story_ids.append(current_id)
            elif post_time:
                break

        current_id -= 1
        time.sleep(0.1)

    print(f"🎯 Done checking. Total story IDs gathered: {len(story_ids)} (from {checked} checks)\n")
    return story_ids

if __name__ == "__main__":
    ids = get_recent_story_ids(max_count=2000)
    cve_stories = []

    for item_id in ids:
        item = get_item(item_id)
        if item:
            post_time = item.get("time")
            if not post_time or not is_recent(post_time):
                continue

            title = item.get("title", "")
            text = item.get("text", "")
            content = f"{title} {text}"

            cves = CVE_PATTERN.findall(content)
            if cves:
                cve_counts = {cve: cves.count(cve) for cve in set(cves)}
                permalink = f"https://news.ycombinator.com/item?id={item['id']}"
                text_embedding = model.encode(content).tolist()

                comment_texts = get_comments(item.get("kids", []))
                comment_embeddings = [model.encode(comment).tolist() for comment in comment_texts]

                cve_stories.append({
                    "permalink": permalink,
                    "cves": cves,
                    "cve_counts": cve_counts,
                    "title": title,
                    "text_embedding": text_embedding,
                    "comment_embeddings": comment_embeddings
                })

    output_filename = f"hackernews_cve_{date.today().isoformat()}.json"
    with open(output_filename, "w") as f:
        json.dump(cve_stories, f, indent=2)

    print(f"\n🛡️ Hacker News posts from the past 2 days mentioning 'CVE':\n")
    print(f"🧮 Gathered {len(ids)} story IDs from recent Hacker News history.")

    if cve_stories:
        for post in cve_stories:
            print(f"🔗 {post['permalink']}")
            print(f"📌 Title: {post['title']}")
            print(f"🧠 CVEs found: {post['cves']}")
            print(f"🧾 CVE counts: {post['cve_counts']}\n")
        print(f"✅ Total posts mentioning 'CVE': {len(cve_stories)}")
        print(f"💾 Saved results to {output_filename}")
    else:
        print("⚠️ No posts mentioning 'CVE' found today.")