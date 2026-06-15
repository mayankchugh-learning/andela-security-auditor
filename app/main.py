import logging
from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.database.session import engine
from app.database.models import Base
from app.api.routes import router, limiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Enterprise Security Guardrail Auditor",
    description="Scans Terraform and CloudFormation configs for security misconfigurations.",
    version="1.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.include_router(router)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
