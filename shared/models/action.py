from pydantic import BaseModel


class Action(BaseModel):
    id: str
    type: str
    reason: str | None = None
