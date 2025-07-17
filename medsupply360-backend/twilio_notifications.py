import os
from twilio.rest import Client

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
MANAGER_PHONE_NUMBER = os.getenv("MANAGER_PHONE_NUMBER")

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_stock_alert(message: str):
    client.messages.create(
        body=message,
        from_=TWILIO_PHONE_NUMBER,
        to=MANAGER_PHONE_NUMBER
    )
