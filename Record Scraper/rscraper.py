import os
import re
import csv
import time
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

BASE_URL = "https://therecord.media"
START_URL = f"{BASE_URL}/news"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
OUTPUT_FILE = "record_cve_cleaned.csv"
MAX_ARTICLES = 30

def clean_text(text):
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

def setup_driver():
    options = Options()
    options.add_argument("--headless=new")
    return webdriver.Chrome(options=options)

def fetch_articles(driver, article_driver):
    collected = []
    seen = set()
    fetched_articles = 0
    page = 1

    while fetched_articles < MAX_ARTICLES:
        driver.get(f"{START_URL}?page={page}")
        time.sleep(3)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        article_links = [
            a["href"]
            for a in soup.select("a[href^='/']")
            if (
                a.get("href")
                and re.match(r"^/[^/]+$", a["href"])
                and not any(x in a["href"] for x in ["/tags/", "/category/", "/news/", "/podcast", "/subscribe", "/about", "/contact"])
            )
        ]

        unique_articles = [href for href in article_links if href not in seen]
        seen.update(unique_articles)
        if not unique_articles:
            break
        for href in unique_articles:
            if fetched_articles >= MAX_ARTICLES:
                break

            article_url = BASE_URL + href
            
            try:
                article_driver.get(article_url)
                time.sleep(2)
                article_soup = BeautifulSoup(article_driver.page_source, "html.parser")
                title_tag = article_soup.find("h1")
                title = title_tag.get_text(strip=True) if title_tag else "Untitled"
                date_tag = article_soup.find("time")
                date = date_tag["datetime"][:10] if date_tag and date_tag.has_attr("datetime") else datetime.today().strftime("%Y-%m-%d")

                content_block = article_soup.find("article") or article_soup.find("div", {"class": lambda x: x and "article" in x.lower()})
                if not content_block:
                    fetched_articles += 1
                    continue
                paragraphs = content_block.find_all("p")
                text_content = "\n".join(p.get_text(strip=True) for p in paragraphs)
                content = f"{title} {text_content}"
                
                cve_matches = CVE_PATTERN.findall(content)
                if cve_matches:
                    collected.append((set(cve_matches), {
                        "date": date,
                        "title": title,
                        "text": text_content,
                        "source": "record"
                    }))
            except Exception as e:
                print(f"Error processing article {article_url}: {e}")

            fetched_articles += 1
        page += 1
    return collected

def save_to_csv(data, file_path):
    file_exists = os.path.exists(file_path)
    with open(file_path, "a", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve", "timestamp", "source", "text"])
        if not file_exists:
            writer.writeheader()

        for cves, info in data:
            for cve in cves:
                writer.writerow({
                    "cve": cve,
                    "timestamp": info["date"],
                    "source": info["source"],
                    "text": clean_text(f"{info['title']} {info['text']}")
                })

def main():
    driver = setup_driver()
    article_driver = setup_driver()
    try:
        collected = fetch_articles(driver, article_driver)
        save_to_csv(collected, OUTPUT_FILE)
    finally:
        driver.quit()
        article_driver.quit()

if __name__ == "__main__":
    main()