import json
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time

# CVE pattern regex
CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

options = Options()
options.add_argument("--headless=new")
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

# Combine articles
articles = []
if "briefs" in page_props:
    articles.extend(page_props["briefs"])
if "latestNewsItems" in page_props:
    articles.extend(page_props["latestNewsItems"])

seen = set()
results = []

for article in articles:
    date_str = article["attributes"]["date"][:10]
    if date_str != TARGET_DATE:
        continue

    title = article["attributes"]["title"]
    slug = article["attributes"]["page"]["data"]["attributes"]["slug"]
    url = f"{BASE_URL}{slug}"

    # Skip duplicates
    if url in seen:
        continue
    seen.add(url)

    # Visit article page
    driver.get(url)
    time.sleep(2)
    article_soup = BeautifulSoup(driver.page_source, "html.parser")

    content_block = article_soup.find("article") or article_soup.find("div", {"class": lambda x: x and "article" in x.lower()})
    if not content_block:
        continue

    paragraphs = content_block.find_all("p")
    text_content = "\n".join(p.get_text(strip=True) for p in paragraphs)

    # Match CVEs
    cve_matches = CVE_REGEX.findall(title + " " + text_content)
    if not cve_matches:
        continue

    # Count CVEs
    cve_counts = {}
    for cve in cve_matches:
        cve_counts[cve] = cve_counts.get(cve, 0) + 1

    # Build entry
    entry = {
        "cves": list(set(cve_matches)),
        "cve_counts": cve_counts,
        "title": title,
        "permalink": url,
        "text": text_content,
        "comments": []  # No comment scraping for now
    }

    results.append(entry)

# Save to file
with open("record_cve.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ DONE. Saved {len(results)} CVE-related article(s) to record_cve.json.")
driver.quit()