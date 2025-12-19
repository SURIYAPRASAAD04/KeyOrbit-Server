from datetime import datetime, timezone
import pytz
from app.models import ApiToken
from app.utils.security import get_current_ist_datetime
import threading
import time

class TokenCleanupService:
    def __init__(self):
        self.is_running = False
        self.cleanup_thread = None
        self.cleanup_interval = 3600  # 1 hour in seconds
    
    def start(self):
        """Start the cleanup service in a background thread"""
        if not self.is_running:
            self.is_running = True
            self.cleanup_thread = threading.Thread(target=self._run_cleanup_loop, daemon=True)
            self.cleanup_thread.start()
            print(f"Token cleanup service started (interval: {self.cleanup_interval}s)")
    
    def stop(self):
        """Stop the cleanup service"""
        if self.is_running:
            self.is_running = False
            if self.cleanup_thread:
                self.cleanup_thread.join(timeout=5)
            print("Token cleanup service stopped")
    
    def _run_cleanup_loop(self):
        """Run cleanup in a loop"""
        while self.is_running:
            try:
                self.cleanup_expired_tokens()
            except Exception as e:
                print(f"Error in cleanup loop: {str(e)}")
            
            # Sleep for the interval, checking is_running periodically
            for _ in range(self.cleanup_interval):
                if not self.is_running:
                    break
                time.sleep(1)
    
    def cleanup_expired_tokens(self):
        """Clean up expired tokens"""
        try:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking for expired tokens...")
            
            current_utc = datetime.now(timezone.utc)
            if current_utc.tzinfo is None:
                current_utc = pytz.utc.localize(current_utc)
            
            # Find active tokens that have expired
            expired_tokens = ApiToken.collection.find({
                "status": "active",
                "expiresAt": {"$lt": current_utc}
            })
            
            count = 0
            for token in expired_tokens:
                # Mark as expired
                ApiToken.collection.update_one(
                    {"_id": token["_id"]},
                    {"$set": {
                        "status": "expired", 
                        "updatedAt": get_current_ist_datetime()
                    }}
                )
                count += 1
            
            if count > 0:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Marked {count} tokens as expired")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No expired tokens found")
            
            return count
            
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error cleaning up expired tokens: {str(e)}")
            return 0
    
    def cleanup_now(self):
        """Manually trigger cleanup"""
        return self.cleanup_expired_tokens()
    
    def set_cleanup_interval(self, seconds):
        """Set cleanup interval in seconds"""
        if seconds > 0:
            self.cleanup_interval = seconds
            print(f"Cleanup interval set to {seconds} seconds")

# Global instance
token_cleanup_service = TokenCleanupService()