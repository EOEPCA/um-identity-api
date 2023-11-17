#!/usr/bin/env python3

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.configuration import get_settings
from app.error_handling import exception_handler
from app.routers import clients, health, policies, resources, clients_permissions, clients_resources, clients_policies

settings = get_settings()
app = FastAPI(
    title="Identity API Documentation",
    description="API endpoints",
    version=settings.version,
)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origins=["*"],
)
exception_handler(app)
app.include_router(clients.router)
app.include_router(clients_permissions.router)
app.include_router(clients_policies.router)
app.include_router(clients_resources.router)
app.include_router(policies.router)
app.include_router(resources.router)
app.include_router(health.router)


@app.get("/", include_in_schema=False)
async def docs_redirect():
    return RedirectResponse(url='/docs')


def main() -> None:
    uvicorn.run("main:app", host="0.0.0.0")


if __name__ == "__main__":
    main()