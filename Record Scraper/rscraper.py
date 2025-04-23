import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time

options = Options()
options.add_argument("--headless")
driver = webdriver.Chrome(options=options)

BASE_URL = "https://therecord.media"
START_URL = f"{BASE_URL}/news/cybercrime"
TARGET_DATE = "2025-04-16"

print("[1] Launching browser and fetching page...")
driver.get(START_URL)
time.sleep(3)

soup = BeautifulSoup(driver.page_source, "html.parser")
next_data_script = soup.find("script", id="__NEXT_DATA__")

if not next_data_script:
    print("❌ Could not find Next.js data block.")
    driver.quit()
    exit()

next_data = json.loads(next_data_script.string)
page_props = next_data["props"]["pageProps"]

# Combine both briefs and latestNewsItems
articles = []
if "briefs" in page_props:
    articles.extend(page_props["briefs"])
if "latestNewsItems" in page_props:
    articles.extend(page_props["latestNewsItems"])

seen = set()
match_count = 0

for article in articles:
    date_str = article["attributes"]["date"][:10]
    if date_str == TARGET_DATE:
        title = article["attributes"]["title"]
        slug = article["attributes"]["page"]["data"]["attributes"]["slug"]
        url = f"{BASE_URL}{slug}"

        # Skip duplicates
        if url in seen:
            continue
        seen.add(url)

        print(f"\n✅ MATCHED ARTICLE")
        print(f"🔹 Title: {title}")
        print(f"🔗 URL: {url}")
        match_count += 1

        # Fetch article content
        driver.get(url)
        time.sleep(2)  # allow page to load
        article_soup = BeautifulSoup(driver.page_source, "html.parser")

        # Look for main article content
        content_block = article_soup.find("article")
        if not content_block:
            content_block = article_soup.find("div", {"class": lambda x: x and "article" in x.lower()})

        # Extract text
        if content_block:
            paragraphs = content_block.find_all("p")
            text_content = "\n".join(p.get_text(strip=True) for p in paragraphs)
            print(f"\n📝 TEXT:\n{text_content[:1000]}...")  # limit to 1000 chars for display
        else:
            print("\n⚠️ Could not find article content.")

print(f"\n✅ DONE. Found {match_count} posts from {TARGET_DATE}.")
driver.quit()