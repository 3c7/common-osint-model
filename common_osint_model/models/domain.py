from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel


class Entity(BaseModel):
    """Represents an entity which registered a domain."""
    name: Optional[str]
    email: Optional[str]
    organization: Optional[str]
    street: Optional[str]
    city: Optional[str]
    postal_code: Optional[str]
    country: Optional[str]
    phone: Optional[str]
    timestamp: datetime = datetime.utcnow()


class Domain(BaseModel):
    """Represents a domain pointing to a specific host."""
    domain: str
    first_seen: datetime = datetime.utcnow()
    last_seen: datetime = datetime.utcnow()
    source: Optional[str]
    type: Optional[str]
    soa: Optional[List[str]]
    nameserver: Optional[List[str]]
    registrar: Optional[str]
    registrant: Optional[Entity]
