import requests
import json

url_timelines = 'https://mastodon.social/api/v1/timelines/public'
url_hashtags = 'https://mastodon.social/api/v1/timelines/tag/cve'
rate_limit = "40"
cve_posts = []
post_ids = []
# post_ids_scraped = open("post_ids.json", "r", encoding="utf-8")
#array for json

def contains_cve(post):
    return "cve" in post or "CVE" in post

# def is_scraped(id):
#
for x in range(100):
    r = requests.get(url_timelines, params=rate_limit)  # limit to 40 posts from the timelines
    toots = json.loads(r.text)
    for t in toots:
        #check if the post includes cve
        #extract the cve
        #append to the file
        if "CVE" in (t['content']):
            print(t['content'])
            cve_posts.append(t['content'])


for x in range(10):
    r = requests.get(url_hashtags, params=rate_limit)
    post = json.loads(r.text)
    for t in post:
        if "CVE" in  (t['content']):
            if contains_cve(t['content']):
                post = {"body": t['content'], "id": t['id'], "created_at": t['created_at']}

                cve_posts.append(post)

with open("cve_posts.json", "w", encoding="utf-8") as f:
    json.dump(cve_posts, f, ensure_ascii=False, indent=2)




