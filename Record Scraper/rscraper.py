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
TARGET_DATE = "2025-04-22"

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
articles = next_data["props"]["pageProps"]["briefs"]

match_count = 0
for article in articles:
    date_str = article["attributes"]["date"][:10]
    if date_str == TARGET_DATE:
        title = article["attributes"]["title"]
        slug = article["attributes"]["page"]["data"]["attributes"]["slug"]
        print(f"\n✅ MATCHED ARTICLE")
        print(f"🔹 Title: {title}")
        print(f"🔗 URL: {BASE_URL}{slug}")
        match_count += 1

print(f"\n✅ DONE. Found {match_count} posts from {TARGET_DATE}.")
driver.quit()