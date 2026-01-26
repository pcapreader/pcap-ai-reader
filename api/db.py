import os
from supabase import create_client
from dotenv import load_dotenv

# Load .env file
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is missing")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
