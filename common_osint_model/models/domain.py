from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Domain(BaseModel):
    """Represents a domain pointing to a specific host."""
    domain: str
    first_seen: datetime = datetime.utcnow()
    last_seen: datetime = datetime.utcnow()
    source: Optional[str]
    type: Optional[str]
