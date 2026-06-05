from datetime import datetime, UTC

from pydantic import BaseModel, Field


class Entity(BaseModel):
    """Represents an entity which registered a domain."""
    name: str | None = None
    email: str | None = None
    organization: str | None = None
    street: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    phone: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Domain(BaseModel):
    """Represents a domain pointing to a specific host. Also, this object might be used to represent found via other
    sources, therefore a 'query' field might contain the query used to find it"""
    domain: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str | None = None
    type: str | None = None
    soa: list[str] | None = None
    nameserver: list[str] | None = None
    registrar: str | None = None
    registrant: Entity | None = None
    query: str | None = None
