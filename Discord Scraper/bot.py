import discord
import re
import os
import json
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
TOKEN = os.getenv('DISCORD_BOT_TOKEN')

CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True

client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f'Bot is online as {client.user}')

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    cve_matches = CVE_PATTERN.findall(message.content)
    if cve_matches:
        print(f"[CVE Found] {message.channel} | {message.author}: {message.content}")

        message_data = {
            "cve_matches": cve_matches,
            "content": message.content,
            "author": str(message.author),
            "channel": str(message.channel),
            "timestamp": message.created_at.isoformat()
        }

        filename = "cve_messages.json"
        if os.path.exists(filename):
            with open(filename, "r") as f:
                try:
                    existing_data = json.load(f)
                except json.JSONDecodeError:
                    existing_data = []
        else:
            existing_data = []

        existing_data.append(message_data)

        with open(filename, "w") as f:
            json.dump(existing_data, f, indent=2)

client.run(TOKEN)
