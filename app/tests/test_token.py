import sys
sys.path.append('.')

from app.utils.security import verify_password
from pymongo import MongoClient
from app.config import Config

# Connect to DB
client = MongoClient(Config.MONGODB_URI)
db = client.keyorbit

# Get all tokens
tokens = list(db.api_tokens.find({}))

print(f"Total tokens in DB: {len(tokens)}\n")

for t in tokens:
    print(f"Token Name: {t.get('name')}")
    print(f"Token Preview: {t.get('tokenPreview')}")
    print(f"Token Hash in DB: {t.get('tokenHash', '')[:60]}...")
    print(f"Status: {t.get('status')}")
    print(f"Created: {t.get('createdAt')}")
    print("-" * 50)

# Test the token you're trying to use
test_token = "CJYXedlGemlbg1-vCsOGA-RTRU_a5HBVY7rjzoHjxT6eZ0GQED8afuPrkfD2mDLF90S0c4ZrWIorf__zzB6mDQ"

print(f"\nTesting token: {test_token[:20]}...")
print(f"Token length: {len(test_token)}")

# Check if any token in DB matches this hash USING VERIFY_PASSWORD
matches_found = 0
for t in tokens:
    db_hash = t.get('tokenHash')
    if verify_password(test_token, db_hash):
        print(f"\n✓ ✓ ✓ MATCH FOUND! Token '{t.get('name')}' matches your test token")
        print(f"  Token ID: {t.get('_id')}")
        matches_found += 1

if matches_found == 0:
    print("\n✗ No token in DB matches your test token")
    print("\nDebugging info:")
    print(f"Token preview from DB: {tokens[0].get('tokenPreview')}")
    print(f"First 20 chars of your token: {test_token[:20]}")
    print(f"Token preview should be: ko_{test_token[:16]}")
    
    # Check if token preview matches
    expected_preview = f"ko_{test_token[:16]}"
    actual_preview = tokens[0].get('tokenPreview')
    if expected_preview == actual_preview:
        print(f"✓ Token preview matches: {expected_preview}")
    else:
        print(f"✗ Token preview MISMATCH!")
        print(f"  Expected: {expected_preview}")
        print(f"  Actual: {actual_preview}")