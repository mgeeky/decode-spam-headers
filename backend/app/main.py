from fastapi import FastAPI

from app.core.config import get_settings
from app.middleware.rate_limiter import RateLimiterMiddleware, SlidingWindowRateLimiter
from app.routers.analysis import router as analysis_router
from app.routers.captcha import router as captcha_router
from app.routers.tests import router as tests_router

app = FastAPI(title="Web Header Analyzer API")
settings = get_settings()
rate_limiter = SlidingWindowRateLimiter(
    settings.rate_limit_requests, settings.rate_limit_window_seconds
)
app.add_middleware(
    RateLimiterMiddleware, limiter=rate_limiter, protected_paths={"/api/analyse"}
)
app.include_router(analysis_router)
app.include_router(captcha_router)
app.include_router(tests_router)


@app.get("/")
def read_root() -> dict[str, str]:
    return {"status": "ok"}
