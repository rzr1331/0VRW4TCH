from fastapi import FastAPI

app = FastAPI(title="Autonomous SecOps Platform")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
