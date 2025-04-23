import re
import json
import requests
from bs4 import BeautifulSoup
import time

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Referer": "https://www.google.com/",
}

BASE_URL = "https://www.bleepingcomputer.com/"
TARGET_DATE = "April 22, 2025"
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

try:
    response = requests.get(BASE_URL, headers=HEADERS)
    response.raise_for_status()
except requests.RequestException as e:
    raise SystemExit(f"Error fetching homepage: {e}")

soup = BeautifulSoup(response.text, "html.parser")
date_tags = soup.find_all("li", class_="bc_news_date")

results = []

for date_tag in date_tags:
    if date_tag.get_text(strip=True) == TARGET_DATE:
        meta_ul = date_tag.find_parent("ul")
        container = meta_ul.find_parent() if meta_ul else None
        if not container:
            continue

        title_tag = container.find("h4") or container.find("h3")
        link_tag = title_tag.find("a") if title_tag else None
        if not link_tag:
            continue

        title = link_tag.get_text(strip=True)
        href = link_tag["href"]
        full_url = href if href.startswith("http") else BASE_URL.rstrip("/") + href

        try:
            time.sleep(1)
            article_response = requests.get(full_url, headers=HEADERS)
            article_response.raise_for_status()
            article_soup = BeautifulSoup(article_response.text, "html.parser")
        except requests.RequestException:
            continue

        content = ""
        for tag in article_soup.find_all("p"):
            content += tag.get_text(separator=" ", strip=True) + " "

        cves = list(set(cve_pattern.findall(title + " " + content)))
        if cves:
            entry = {
                "cves": cves,
                "cve_counts": {cve: content.count(cve) for cve in cves},
                "title": title,
                "permalink": full_url,
                "text": content.strip(),
                "comments": []
            }
            results.append(entry)

with open("bleepingcomputer_scraper.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"✅ DONE. Found {len(results)} CVE-related articles.")