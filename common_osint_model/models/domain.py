from datetime import datetime, UTC
from typing import Optional, List

from pydantic import BaseModel


class Entity(BaseModel):
    """Represents an entity which registered a domain."""
    name: Optional[str]
    email: Optional[str]
    organization: Optional[str]
    street: Optional[str]
    city: Optional[str]
    state: Optional[str]
    postal_code: Optional[str]
    country: Optional[str]
    phone: Optional[str]
    timestamp: datetime = datetime.now(UTC)


class Domain(BaseModel):
    """Represents a domain pointing to a specific host. Also, this object might be used to represent found via other
    sources, therefore a 'query' field might contain the query used to find it"""
    domain: str
    first_seen: datetime = datetime.now(UTC)
    last_seen: datetime = datetime.now(UTC)
    source: Optional[str]
    type: Optional[str]
    soa: Optional[List[str]]
    nameserver: Optional[List[str]]
    registrar: Optional[str]
    registrant: Optional[Entity]
    query: Optional[str]
