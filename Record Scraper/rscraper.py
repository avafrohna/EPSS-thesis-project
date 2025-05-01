import json
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time

CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

options = Options()
options.add_argument("--headless=new")
driver = webdriver.Chrome(options=options)

BASE_URL = "https://therecord.media"
START_URL = f"{BASE_URL}/news/cybercrime"

results = []
seen = set()

driver.get(START_URL)
time.sleep(3)
soup = BeautifulSoup(driver.page_source, "html.parser")
next_data_script = soup.find("script", id="__NEXT_DATA__")
if not next_data_script:
    print("❌ Could not find Next.js data block.")
else:
    next_data = json.loads(next_data_script.string)
    page_props = next_data["props"]["pageProps"]
    
    articles = []
    if "briefs" in page_props:
        articles.extend(page_props["briefs"])
    if "latestNewsItems" in page_props:
        articles.extend(page_props["latestNewsItems"])

    for article in articles:
        date_str = article["attributes"]["date"][:10]
        title = article["attributes"]["title"]
        slug = article["attributes"]["page"]["data"]["attributes"]["slug"]
        article_url = f"{BASE_URL}{slug}"

        if article_url in seen:
            continue
        seen.add(article_url)

        driver.get(article_url)
        time.sleep(2)
        article_soup = BeautifulSoup(driver.page_source, "html.parser")

        content_block = article_soup.find("article") or article_soup.find("div", {"class": lambda x: x and "article" in x.lower()})
        if not content_block:
            continue

        paragraphs = content_block.find_all("p")
        text_content = "\n".join(p.get_text(strip=True) for p in paragraphs)

        cve_matches = CVE_REGEX.findall(title + " " + text_content)
        if not cve_matches:
            continue

        cve_counts = {}
        for cve in cve_matches:
            cve_counts[cve] = cve_counts.get(cve, 0) + 1

        entry = {
            "cves": list(set(cve_matches)),
            "cve_counts": cve_counts,
            "title": title,
            "permalink": article_url,
            "text": text_content,
            "comments": []
        }

        results.append(entry)

try:
    with open("record_cve.json", "r") as f:
        existing_data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    existing_data = []

existing_links = {entry["permalink"] for entry in existing_data}
new_results = [entry for entry in results if entry["permalink"] not in existing_links]
combined_data = existing_data + new_results
with open("record_cve.json", "w") as f:
    json.dump(combined_data, f, indent=2)

print(f"\n✅ DONE. Saved {len(new_results)} new CVE-related article(s) to record_cve.json.")
driver.quit()