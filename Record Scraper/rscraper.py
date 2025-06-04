import json
import re
import csv
import os
import time
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

BASE_URL = "https://therecord.media"
START_URL = f"{BASE_URL}/news"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
output_file = "record_cve_cleaned.csv"

def clean_text(text):
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

options = Options()
options.add_argument("--headless=new")
driver = webdriver.Chrome(options=options)
article_driver = webdriver.Chrome(options=options)

print("📄 Fetching Record articles...")

collected = []
seen = set()
max_articles = 30
fetched_articles = 0
page = 1

while fetched_articles < max_articles:
    print(f"🌐 Loading page {page}...")
    driver.get(f"{START_URL}?page={page}")
    time.sleep(3)
    soup = BeautifulSoup(driver.page_source, "html.parser")

    article_links = [
        a["href"]
        for a in soup.select("a[href^='/']")
        if (
            a.get("href")
            and re.match(r"^/[^/]+$", a["href"])  # only top-level slugs like /slug-title
            and not any(x in a["href"] for x in ["/tags/", "/category/", "/news/", "/podcast", "/subscribe", "/about", "/contact"])
        )
    ]

    unique_articles = []
    for href in article_links:
        if href in seen:
            continue
        seen.add(href)
        unique_articles.append(href)

    if not unique_articles:
        break

    for href in unique_articles:
        if fetched_articles >= max_articles:
            break

        article_url = BASE_URL + href
        print(f"🔄 Processing article {fetched_articles + 1}: {article_url}")

        try:
            article_driver.get(article_url)
            time.sleep(2)
            article_soup = BeautifulSoup(article_driver.page_source, "html.parser")

            # Extract title
            title_tag = article_soup.find("h1")
            title = title_tag.get_text(strip=True) if title_tag else "Untitled"

            # Extract date
            date_tag = article_soup.find("time")
            date = date_tag["datetime"][:10] if date_tag and date_tag.has_attr("datetime") else datetime.today().strftime("%Y-%m-%d")

            # Extract content
            content_block = article_soup.find("article") or article_soup.find("div", {"class": lambda x: x and "article" in x.lower()})
            if not content_block:
                fetched_articles += 1
                continue

            paragraphs = content_block.find_all("p")
            text_content = "\n".join(p.get_text(strip=True) for p in paragraphs)
            content = f"{title} {text_content}"

            cve_matches = CVE_PATTERN.findall(content)
            if cve_matches:
                print(f"🔎 Found CVEs in article: {set(cve_matches)}")
                collected.append((set(cve_matches), {
                    "date": date,
                    "title": title,
                    "text": text_content,
                    "source": "record"
                }))
        except Exception as e:
            print(f"❌ Error processing article: {e}")

        fetched_articles += 1
    page += 1

print(f"📊 Finished scraping {fetched_articles} articles in total.")
file_exists = os.path.exists(output_file)

with open(output_file, "a", newline='', encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["cve", "timestamp", "source", "text"])
    if not file_exists:
        writer.writeheader()

    for cves, info in collected:
        for cve in cves:
            if not re.match(r'CVE-\d{4}-\d{4,7}', cve):
                continue
            writer.writerow({
                "cve": cve,
                "timestamp": info["date"],
                "source": "record",
                "text": clean_text(f"{info['title']} {info['text']}")
            })

print(f"\n✅ CSV file updated with {sum(len(cves) for cves, _ in collected)} CVE entries from The Record.")
driver.quit()
article_driver.quit()