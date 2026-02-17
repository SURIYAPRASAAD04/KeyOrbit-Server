from app.models import User, AuditLog
from bson import ObjectId

# Get your user
user = User.find_by_email("btechit221729@smvec.ac.in")
print(f"User: {user['email']}")
print(f"User ID: {user['_id']}")
print(f"Organization ID: {user.get('organizationId')}")

# Count logs for this organization
count = AuditLog.collection.count_documents({
    "organizationId": user.get('organizationId')
})
print(f"\nTotal logs for organization: {count}")

# Show recent logs
logs = AuditLog.collection.find({
    "organizationId": user.get('organizationId')
}).sort("timestamp", -1).limit(5)

print("\nRecent logs:")
for log in logs:
    print(f"- {log['timestamp']}: {log['actionType']} (User: {log.get('userId')})")