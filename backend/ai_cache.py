# backend/ai_cache.py
import hashlib
import asyncio
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass, field

@dataclass
class AICacheEntry:
    status: str          # "pending" | "done" | "error"
    summary: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

class AIResultCache:
    """Cache in-memory thread-safe pour les résultats IA."""
    
    TTL_SECONDS = 300  # 5 minutes
    MAX_ENTRIES = 500
    
    def __init__(self):
        self._store: dict[str, AICacheEntry] = {}
        self._lock = asyncio.Lock()
    
    @staticmethod
    def make_key(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]
    
    async def set_pending(self, key: str) -> None:
        async with self._lock:
            self._store[key] = AICacheEntry(status="pending")
    
    async def set_done(self, key: str, summary: Optional[str]) -> None:
        async with self._lock:
            entry = self._store.get(key)
            if entry:
                entry.status = "done"
                entry.summary = summary
    
    async def set_error(self, key: str, error: str) -> None:
        async with self._lock:
            entry = self._store.get(key)
            if entry:
                entry.status = "error"
                entry.error = error
    
    async def get(self, key: str) -> Optional[AICacheEntry]:
        async with self._lock:
            entry = self._store.get(key)
            if entry and datetime.utcnow() - entry.created_at > timedelta(seconds=self.TTL_SECONDS):
                del self._store[key]
                return None
            return entry
    
    async def evict_old(self) -> None:
        """Appeler périodiquement pour éviter les fuites mémoire."""
        async with self._lock:
            now = datetime.utcnow()
            expired = [k for k, v in self._store.items()
                       if now - v.created_at > timedelta(seconds=self.TTL_SECONDS)]
            for k in expired:
                del self._store[k]

# Singleton partagé
ai_cache = AIResultCache()
