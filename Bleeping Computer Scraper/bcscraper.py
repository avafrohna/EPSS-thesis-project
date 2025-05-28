import re
import csv
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import time
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1",
]

HEADERS = {
    "User-Agent": random.choice(USER_AGENTS),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Referer": "https://www.google.com/",
}

BASE_URL = "https://www.bleepingcomputer.com/"
TARGET_DATE = "2025-05-26"
target_date = datetime.strptime(TARGET_DATE, "%Y-%m-%d").date()
found_target = False
stop_scraping = False
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

results = []
page = 1

while page <= 100:
    page_url = BASE_URL if page == 1 else f"{BASE_URL}page/{page}/"
    try:
        response = requests.get(page_url, headers=HEADERS)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"⚠️ Failed to fetch page {page}: {e}")
        break

    print(f"📄 Scraping page {page}...")

    soup = BeautifulSoup(response.text, "html.parser")
    date_tags = soup.find_all("li", class_="bc_news_date")
    if not date_tags:
        date_tags = soup.find_all("span", class_="bc_news_date")

    if not date_tags:
        print("⚠️ No date tags found. Ending pagination.")
        break

    for date_tag in date_tags:
        date_text = date_tag.get_text(strip=True)
        try:
            formatted_date = datetime.strptime(date_text, "%B %d, %Y").strftime("%Y-%m-%d")
            article_date = datetime.strptime(formatted_date, "%Y-%m-%d").date()
        except ValueError as e:
            print(f"⚠️ Failed to parse date '{date_text}': {e}")
            continue
        
        if article_date == target_date:
            found_target = True
        elif article_date < target_date and found_target:
            stop_scraping = True
            break
        elif not found_target:
            continue

        container = date_tag.find_parent("li")
        if not container:
            print("⚠️ Failed to find article container for date tag.")
            continue

        title_tag = container.find("h4") or container.find("h3")
        link_tag = title_tag.find("a") if title_tag else None
        if not link_tag or not link_tag.get("href"):
            print("⚠️ No link found for article, skipping...")
            continue

        title = link_tag.get_text(strip=True)
        href = link_tag["href"]
        full_url = href if href.startswith("http") else BASE_URL.rstrip("/") + href
            
        try:
            time.sleep(random.uniform(2, 5))
            article_response = requests.get(full_url, headers=HEADERS)
            article_response.raise_for_status()
            article_soup = BeautifulSoup(article_response.text, "html.parser")
        except requests.RequestException as e:
            print(f"⚠️ Failed to fetch article '{full_url}': {e}")
            continue

        content = ""
        article_body = article_soup.find("div", class_="articleBody")
        if article_body:
            paragraphs = article_body.find_all("p")
            content = " ".join(p.get_text(strip=True) for p in paragraphs)

        cves = list(set(cve_pattern.findall(title + " " + content)))
        if cves:
            entry = {
                "cves": cves,
                "cve_counts": {cve: content.count(cve) for cve in cves},
                "date": formatted_date,
                "title": title,
                "link": full_url,
                "text": content.strip(),
            }
            results.append(entry)

    if stop_scraping:
        break

    page += 1

csv_file = "bleepingcomputer_cve_cleaned.csv"
fieldnames = ["cve", "timestamp", "source", "text"]

with open(csv_file, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if f.tell() == 0:
        writer.writeheader()
    for entry in results:
        for cve in entry["cves"]:
            writer.writerow({
                "cve": cve,
                "timestamp": entry["date"],
                "source": "bleeping computer",
                "text": entry["text"],
            })

print(f"✅ DONE. Found {len(results)} CVE-related articles on {TARGET_DATE}.")