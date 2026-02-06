from pydantic import BaseModel, Field


class Asset(BaseModel):
    id: str = Field(..., description="Unique asset identifier")
    type: str = Field(..., description="Asset type, e.g. host, service, db")
    owner: str | None = None
    criticality: str | None = None
