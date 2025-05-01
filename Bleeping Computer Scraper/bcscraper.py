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
TARGET_DATE = "April 28, 2025"
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

results = []
page = 1

while True:
    page_url = BASE_URL if page == 1 else f"{BASE_URL}page/{page}/"
    try:
        response = requests.get(page_url, headers=HEADERS)
        response.raise_for_status()
    except requests.RequestException:
        break  # Stop if the page fails to load

    soup = BeautifulSoup(response.text, "html.parser")
    date_tags = soup.find_all("li", class_="bc_news_date")

    if not date_tags:
        break  # No more news items found

    for date_tag in date_tags:
        date_text = date_tag.get_text(strip=True)
        if date_text != TARGET_DATE:
            continue
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

    pagination = soup.find("ul", class_="cz-pagination")
    if not pagination or not pagination.find("a", string=str(page + 1)):
        break

    page += 1

# Load existing JSON and append new results
try:
    with open("bleepingcomputer_scraper.json", "r") as f:
        existing_data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    existing_data = []

with open("bleepingcomputer_scraper.json", "w") as f:
    json.dump(existing_data + results, f, indent=2)

print(f"✅ DONE. Found {len(results)} CVE-related articles.")