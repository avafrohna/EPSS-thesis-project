import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime

# Configurable target date (YYYY-MM-DD)
TARGET_DATE = "2025-04-19"

# Helper to extract CVEs
def extract_cves(text):
    return re.findall(r'CVE-\d{4}-\d{4,7}', text, flags=re.IGNORECASE)

# Get questions list
url = "https://stackoverflow.com/questions"
headers = {"User-Agent": "Mozilla/5.0"}

response = requests.get(url, headers=headers)
soup = BeautifulSoup(response.text, "html.parser")
question_summaries = soup.find_all("div", class_="s-post-summary")

found_any = False

for i, summary in enumerate(question_summaries, start=1):
    title_elem = summary.find("a", class_="s-link")
    if not title_elem:
        continue

    title = title_elem.get_text().strip()
    link = "https://stackoverflow.com" + title_elem["href"]

    # Visit individual question page
    post_res = requests.get(link, headers=headers)
    post_soup = BeautifulSoup(post_res.text, "html.parser")

    # Extract date/time
    time_tag = post_soup.find("time")
    if not time_tag or "datetime" not in time_tag.attrs:
        continue

    post_time_str = time_tag["datetime"]
    try:
        post_time = datetime.fromisoformat(post_time_str.replace("Z", "+00:00"))
    except ValueError:
        continue

    if post_time.date().isoformat() != TARGET_DATE:
        continue

    # Extract content
    content_elem = post_soup.find("div", class_="s-prose js-post-body")
    content_text = content_elem.get_text().strip() if content_elem else ""

    # Extract CVEs from title + content
    found_cves = extract_cves(title + " " + content_text)
    if not found_cves:
        continue  # Only print if CVEs exist

    found_any = True
    print(f"{i}. {title}")
    print(f"   🕓 Posted: {post_time}")
    print(f"   🔗 Link: {link}")
    print(f"   📄 Snippet: {content_text[:200]}...")
    print(f"   ✅ CVE(s): {', '.join(found_cves)}")
    print("-" * 80)

if not found_any:
    print("No CVEs found.")