from fastapi import FastAPI

from overwatch_platform.api.dashboard import router as dashboard_router
from overwatch_platform.api.chat import router as chat_router

app = FastAPI(title="0VRW4TCH — Autonomous SecOps Platform")

app.include_router(dashboard_router)
app.include_router(chat_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
