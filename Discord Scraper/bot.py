import discord
import re
import os
from dotenv import load_dotenv

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

    if CVE_PATTERN.search(message.content):
        print(f"[CVE Found] {message.channel} | {message.author}: {message.content}")

client.run(TOKEN)
