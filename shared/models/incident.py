from pydantic import BaseModel, Field
from datetime import datetime


class Incident(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
