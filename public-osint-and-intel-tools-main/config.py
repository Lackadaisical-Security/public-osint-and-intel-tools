import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Keys (Optional - tools will work without them but with limited functionality)
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    TWITTER_API_KEY = os.getenv('TWITTER_API_KEY', '')
    TWITTER_API_SECRET = os.getenv('TWITTER_API_SECRET', '')
    TWITTER_ACCESS_TOKEN = os.getenv('TWITTER_ACCESS_TOKEN', '')
    TWITTER_ACCESS_SECRET = os.getenv('TWITTER_ACCESS_SECRET', '')
    
    # Rate limiting
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    
    # User agent for web requests
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
