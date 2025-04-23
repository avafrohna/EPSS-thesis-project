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

try:
    print("[1] Fetching front page...")
    response = requests.get(BASE_URL, headers=HEADERS)
    response.raise_for_status()
except requests.RequestException as e:
    print(f"Error fetching homepage: {e}")
    exit(1)

soup = BeautifulSoup(response.text, "html.parser")

articles = []
date_tags = soup.find_all("li", class_="bc_news_date")

for date_tag in date_tags:
    if date_tag.get_text(strip=True) == TARGET_DATE:
        meta_ul = date_tag.find_parent("ul")
        container = meta_ul.find_parent() if meta_ul else None
        if not container:
            continue

        title_tag = container.find("h4") or container.find("h3")
        if not title_tag:
            continue
        link_tag = title_tag.find("a")
        if not link_tag:
            continue

        title = link_tag.get_text(strip=True)
        href = link_tag["href"]
        full_url = href if href.startswith("http") else BASE_URL.rstrip("/") + href

        # Fetch the article content
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

        content = content.strip()
        preview = content[:1000] + ("..." if len(content) > 1000 else "")

        articles.append((title, full_url, TARGET_DATE, preview))

# Output
if articles:
    for title, url, date, preview in articles:
        print("Title:", title)
        print("URL:", url)
        print("Published Date:", date)
        print("Preview:", preview)
        print("-" * 80)
else:
    print(f"✅ DONE. Found 0 posts from {TARGET_DATE}.")