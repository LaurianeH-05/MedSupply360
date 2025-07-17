# database_config.py
import os
from dotenv import load_dotenv

# Load .env into environment variables
load_dotenv()

# Now read DATABASE_URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+aiomysql://user:password@localhost/db_name")
DATABASE_URL1 = os.getenv("DATABASE_URL1", "mysql+pymysql://user:password@localhost/db_name")

# Ensure DATABASE_URL is set
if not DATABASE_URL or not DATABASE_URL1:
    raise RuntimeError("DATABASE_URL and DATABASE_URL1 is not set in your environment")
