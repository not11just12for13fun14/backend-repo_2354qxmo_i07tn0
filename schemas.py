"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

# ---------------------------
# Insider Threat: Event schema
# ---------------------------
class Event(BaseModel):
    """
    Generic security event
    Collection: "event"
    """
    timestamp: datetime = Field(..., description="Event timestamp (ISO 8601)")
    user: Optional[str] = Field(None, description="User identifier")
    action: Optional[str] = Field(None, description="Action name e.g., login, download, read, write, delete")
    status: Optional[str] = Field(None, description="success/failed/denied/etc")
    resource: Optional[str] = Field(None, description="Target resource e.g., file path, server, application")
    source: Optional[str] = Field(None, description="Source system that generated the event e.g., okta, edr, proxy")
    ip: Optional[str] = Field(None, description="Source IP address")
    device: Optional[str] = Field(None, description="Hostname or device id")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary event metadata")


# ---------------------------
# Insider Threat: Alert schema
# ---------------------------
class Alert(BaseModel):
    """
    Detection alert
    Collection: "alert"
    """
    rule_id: str = Field(..., description="Identifier of the rule that triggered")
    severity: str = Field(..., description="low, medium, high, critical")
    title: str = Field(..., description="Short readable title")
    description: str = Field(..., description="Detailed description")
    user: Optional[str] = Field(None, description="Related user")
    first_seen: datetime = Field(..., description="First event time that contributed")
    last_seen: datetime = Field(..., description="Last event time that contributed")
    count: int = Field(..., description="Number of contributing events")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context such as sample events, IPs, resources")


# Example schemas (left for reference; not used by the insider tool directly)
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")
