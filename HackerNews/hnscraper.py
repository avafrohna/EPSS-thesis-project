import requests
import asyncio
import aiohttp
import time
import re
import json
from datetime import datetime, timezone, date, timedelta
from sentence_transformers import SentenceTransformer
import os

output_filename = "hackernews_cve.json"

existing_data = []
if os.path.exists(output_filename):
    with open(output_filename, "r") as f:
        try:
            existing_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"⚠️ Couldn't load existing JSON: {e}")
            existing_data = []

existing_ids = set(post["permalink"] for post in existing_data)

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

async def fetch_all_items(session, start_id, max_items=10000):
    semaphore = asyncio.Semaphore(20)
    async def safe_get_item(item_id):
        async with semaphore:
            return await get_item(session, item_id)
    tasks = [safe_get_item(item_id) for item_id in range(start_id, start_id - max_items, -1)]
    return await asyncio.gather(*tasks)

def get_recent_story_ids(max_count=2000):
    async def _get():
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{BASE_URL}/maxitem.json") as resp:
                max_id = await resp.json()

            all_items = await fetch_all_items(session, max_id, max_items=50000)

            story_ids = []
            for item in all_items:
                if not item:
                    continue
                if item.get("type") != "story":
                    continue
                if item.get("dead") or item.get("deleted"):
                    continue

                post_time = item.get("time")
                if not post_time or not is_recent(post_time):
                    continue

                title = item.get("title", "").strip()
                if not title:
                    continue

                text = item.get("text", "")
                content = f"{title} {text}"
                cves = CVE_PATTERN.findall(content)

                display_title = title[:60]
                post_num = len(story_ids) + 1

                if cves:
                    print(f"✅ Post {post_num}: '{display_title}' contains CVEs: {cves}")

                story_ids.append(item["id"])
                if len(story_ids) >= max_count:
                    break

            print(f"Done checking. Total story IDs gathered: {len(story_ids)}\n")
            return story_ids

    return asyncio.run(_get())

async def fetch_story_details(ids):
    async def _fetch():
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(20)
            async def fetch_story(item_id):
                async with semaphore:
                    try:
                        return await get_item(session, item_id)
                    except:
                        return None
            tasks = [fetch_story(item_id) for item_id in ids]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r]
    return await _fetch()

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
    ids = get_recent_story_ids(max_count=3000)
    cve_stories = []

    items = asyncio.run(fetch_story_details(ids))

    for item in items:
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

                if permalink not in existing_ids:
                    existing_data.append({
                        "cves": cves,
                        "cve_counts": cve_counts,
                        "title": title,
                        "permalink": permalink,
                        "text": content,
                        "comments": comment_texts,
                    })

    with open(output_filename, "w") as f:
        json.dump(existing_data, f, indent=2)

    print(f"Gathered {len(ids)} story IDs from recent Hacker News history.")

    if cve_stories:
        for post in cve_stories:
            print(f"🔗 {post['permalink']}")
            print(f"Title: {post['title']}")
            print(f"CVEs found: {post['cves']}")
            print(f"CVE counts: {post['cve_counts']}\n")
        print(f"Total posts mentioning 'CVE': {len(cve_stories)}")
        print(f"Saved results to {output_filename}")
    else:
        print("No posts mentioning 'CVE' found today.")