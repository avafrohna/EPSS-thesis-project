import requests
import json

url_timelines = 'https://mastodon.social/api/v1/timelines/public'
url_hashtags = 'https://mastodon.social/api/v1/timelines/tag/cve'
rate_limit = "40"

for x in range(100):
    r = requests.get(url_timelines, params=rate_limit)  # limit to 40 posts from the timelines
    toots = json.loads(r.text)
    for t in toots:
        #check if the post includes cve
        #extract the cve
        #append to the file
        if "CVE" in (t['content']):
            print(t['content'])

for x in range(100):
    r = requests.get(url_hashtags, params=rate_limit)
    post = json.loads(r.text)
    for t in post:
        if "CVE" in  (t['content']):
            print(t['content'])


