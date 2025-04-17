import requests
import asyncio
import aiohttp
import time
import re
import json
from datetime import datetime, timezone, date, timedelta
from sentence_transformers import SentenceTransformer

BASE_URL = "https://hacker-news.firebaseio.com/v0"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
model = SentenceTransformer("all-MiniLM-L6-v2")

def is_recent(unix_time):
    post_dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    return (now_utc - post_dt) <= timedelta(days=2)

async def get_item(session, item_id):
    url = f"{BASE_URL}/item/{item_id}.json"
    async with session.get(url) as resp:
        return await resp.json()

def get_recent_story_ids(max_count=2000):
    async def _get():
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{BASE_URL}/maxitem.json") as resp:
                max_id = await resp.json()

            story_ids = []
            checked = 0
            current_id = max_id
            
            while current_id > 0 and len(story_ids) < max_count:
                item = await get_item(session, current_id)
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
                await asyncio.sleep(0.05)  # respectful async delay

            print(f"🎯 Done checking. Total story IDs gathered: {len(story_ids)} (from {checked} checks)\n")
            return story_ids

    return asyncio.run(_get())

def get_comments(comment_ids):
    comments = []
    if not comment_ids:
        return comments
    for cid in comment_ids:
        try:
            item = requests.get(f"{BASE_URL}/item/{cid}.json").json()
            if item and 'text' in item:
                comments.append(item['text'])
            time.sleep(0.2)
        except Exception:
            continue
    return comments

if __name__ == "__main__":
    ids = get_recent_story_ids(max_count=2000)
    cve_stories = []

    for item_id in ids:
        item = requests.get(f"{BASE_URL}/item/{item_id}.json").json()
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