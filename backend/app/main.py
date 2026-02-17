from fastapi import FastAPI

app = FastAPI(title="Web Header Analyzer API")


@app.get("/")
def read_root() -> dict[str, str]:
    return {"status": "ok"}
