from fastapi import FastAPI

from app.routers.analysis import router as analysis_router
from app.routers.tests import router as tests_router

app = FastAPI(title="Web Header Analyzer API")
app.include_router(analysis_router)
app.include_router(tests_router)


@app.get("/")
def read_root() -> dict[str, str]:
    return {"status": "ok"}
