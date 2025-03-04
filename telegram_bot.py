import logging
from telegram import Bot
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
TELEGRAM_API_TOKEN = os.getenv("TELEGRAM_API_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

# Setup Logging
logging.basicConfig(level=logging.INFO)

class TelegramBot:
    def __init__(self, token=TELEGRAM_API_TOKEN, chat_id=CHAT_ID):
        self.bot = Bot(token=token)
        self.chat_id = chat_id
    
    async def send_message(self, message):
        try:
            await self.bot.send_message(chat_id=self.chat_id, text=message)
            logging.info("Message sent successfully")
        except Exception as e:
            logging.error(f"Error sending message: {e}")

# Function to send a message synchronously
def send_telegram_message(message):
    telegram_bot = TelegramBot()
    asyncio.run(telegram_bot.send_message(message))

# Example usage
if __name__ == "__main__":
    send_telegram_message("Test message from trading bot!")
