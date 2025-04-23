import requests
from bs4 import BeautifulSoup
import re
import json

url = "https://stackoverflow.com/questions"
headers = {"User-Agent": "Mozilla/5.0"}

response = requests.get(url, headers=headers)
soup = BeautifulSoup(response.text, "html.parser")

question_summaries = soup.find_all("div", class_="s-post-summary")

def extract_cves(text):
    return re.findall(r'CVE-\d{4}-\d{4,7}', text)

results = []

for summary in question_summaries:
    time_elem = summary.find("span", class_="relativetime")
    if not time_elem:
        continue
    time_text = time_elem.get_text().strip().lower()
    if not any(kw in time_text for kw in ["ago", "today", "yesterday"]):
        continue

    title_elem = summary.find("a", class_="s-link")
    if not title_elem:
        continue

    title = title_elem.get_text().strip()
    link = "https://stackoverflow.com" + title_elem["href"]

    # Visit the question page to get full content
    post_res = requests.get(link, headers=headers)
    post_soup = BeautifulSoup(post_res.text, "html.parser")

    content_elem = post_soup.find("div", class_="s-prose js-post-body")
    content_text = content_elem.get_text().strip() if content_elem else ""

    found_cves = extract_cves(title + " " + content_text)
    if not found_cves:
        continue

    cve_counts = {cve: 1 for cve in found_cves}

    result_entry = {
        "cves": found_cves,
        "cve_counts": cve_counts,
        "title": title,
        "permalink": link,
        "text": content_text,
        "comments": []  # You can extract comments if needed
    }

    results.append(result_entry)

if results:
    with open("stackoverflow_scraper.json", "w") as f:
        json.dump(results, f, indent=2)
    print("✅ CVE results saved to stackoverflow_scraper.json")
else:
    print("❌ No CVEs found.")