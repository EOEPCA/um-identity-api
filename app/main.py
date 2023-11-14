#!/usr/bin/env python3

import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.dependencies import keycloak_client
from app.routers import clients, health, policies, resources


app = FastAPI(dependencies=[Depends(keycloak_client)])
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origins=["*"],
)
app.include_router(clients.router)
app.include_router(health.router)
app.include_router(policies.router)
app.include_router(resources.router)


@app.exception_handler(500)
async def internal_exception_handler():
    return JSONResponse(status_code=500, content=jsonable_encoder({"code": 500, "msg": "Internal Server Error"}))

@app.exception_handler(400)
async def bad_request_handler():
    return JSONResponse(status_code=400, content=jsonable_encoder({"code": 400, "msg": "Bad request"}))

def main() -> None:
    """Entrypoint to invoke when this module is invoked on the remote server."""
    uvicorn.run("main:app", host="0.0.0.0")

if __name__ == "__main__":
    main()