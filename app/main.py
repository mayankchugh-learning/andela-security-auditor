from fastapi import FastAPI
from app.database.session import engine
from app.database.models import Base
from app.api.routes import router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Enterprise Security Guardrail Auditor",
    description="Scans Terraform and CloudFormation configs for security misconfigurations.",
    version="1.0.0",
)

app.include_router(router)
