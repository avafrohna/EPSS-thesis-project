import re
import json
import csv
import requests
from bs4 import BeautifulSoup
from datetime import datetime
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
TARGET_DATE = "2025-03-20"
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

results = []
page = 1

while page <= 100:
    page_url = BASE_URL if page == 1 else f"{BASE_URL}page/{page}/"
    try:
        response = requests.get(page_url, headers=HEADERS)
        response.raise_for_status()
    except requests.RequestException:
        break

    print(f"📄 Scraping page {page}...")

    soup = BeautifulSoup(response.text, "html.parser")
    date_tags = soup.find_all("li", class_="bc_news_date")

    if not date_tags:
        print("⚠️ No date tags found. Ending pagination.")
        break

    for date_tag in date_tags:
        date_text = date_tag.get_text(strip=True)
        formatted_date = datetime.strptime(date_text, "%B %d, %Y").strftime("%Y-%m-%d")
        if formatted_date != TARGET_DATE:
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
            print(f"✅ Found article on {formatted_date}: {title}")

    print("➡️ Moving to next page...\n")
    page += 1

csv_file = "bleepingcomputer_scraper.csv"
fieldnames = ["cves", "cve_counts", "date", "title", "link", "text"]

with open(csv_file, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if f.tell() == 0:
        writer.writeheader()
    for entry in results:
        writer.writerow({
            "cves": "; ".join(entry["cves"]),
            "cve_counts": json.dumps(entry["cve_counts"]),
            "date": entry["date"],
            "title": entry["title"],
            "link": entry["link"],
            "text": entry["text"],
        })

print(f"✅ DONE. Found {len(results)} CVE-related articles.")