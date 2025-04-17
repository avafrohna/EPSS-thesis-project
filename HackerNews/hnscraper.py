import requests
import time
import re
import json
from datetime import datetime, timezone, date
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

if __name__ == "__main__":
    ids = get_latest_story_ids(limit=2000)
    cve_stories = []

    for item_id in ids:
        item = get_item(item_id)
        if item:
            title = item.get("title", "")
            text = item.get("text", "")
            content = f"{title} {text}"

            if "CVE" in content:
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

    print(f"\n🛡️ Hacker News posts mentioning 'CVE' (most recent {len(ids)} checked):\n")

    if cve_stories:
        for post in cve_stories:
            print(f"🔗 {post['permalink']}")
            print(f"📌 Title: {post['title']}")
            print(f"🧠 CVEs found: {post['cves']}")
            print(f"🧾 CVE counts: {post['cve_counts']}\n")
        print(f"✅ Total posts mentioning 'CVE': {len(cve_stories)}")
        print(f"💾 Saved results to {output_filename}")
    else:
        print("⚠️ No posts mentioning 'CVE' found.")