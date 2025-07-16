# alerts.py
from twilio.rest import Client
import os

from dotenv import load_dotenv
load_dotenv()


# Load from env vars or hardcode for testing
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "your_sid")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "your_token")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "+1234567890")  # Twilio number
TARGET_PHONE_NUMBER = os.getenv("TARGET_PHONE_NUMBER", "+19876543210")  # You

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_stock_alert(message: str):
    client.messages.create(
        body=message,
        from_=TWILIO_PHONE_NUMBER,
        to=TARGET_PHONE_NUMBER,
    )
