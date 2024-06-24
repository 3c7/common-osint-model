from datetime import datetime, UTC
from typing import Optional, List

from pydantic import BaseModel


class Entity(BaseModel):
    """Represents an entity which registered a domain."""
    name: Optional[str] = None
    email: Optional[str] = None
    organization: Optional[str] = None
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    phone: Optional[str] = None
    timestamp: datetime = datetime.now(UTC)


class Domain(BaseModel):
    """Represents a domain pointing to a specific host. Also, this object might be used to represent found via other
    sources, therefore a 'query' field might contain the query used to find it"""
    domain: str
    first_seen: datetime = datetime.now(UTC)
    last_seen: datetime = datetime.now(UTC)
    source: Optional[str] = None
    type: Optional[str] = None
    soa: Optional[List[str]] = None
    nameserver: Optional[List[str]] = None
    registrar: Optional[str] = None
    registrant: Optional[Entity] = None
    query: Optional[str] = None
