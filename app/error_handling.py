import json
from typing import Sequence, Any
import traceback

from fastapi import Request, status, FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.responses import JSONResponse
from keycloak import KeycloakPostError, KeycloakGetError, KeycloakPutError, KeycloakDeleteError


def exception_handler(app: FastAPI) -> None:
    @app.middleware("http")
    async def keycloak_error_handling(request: Request, call_next):
        try:
            return await call_next(request)
        except (KeycloakGetError, KeycloakPostError, KeycloakPutError, KeycloakDeleteError) as e:
            print(traceback.format_exc())
            return JSONResponse(status_code=e.response_code, content=jsonable_encoder(json.loads(e.error_message)))

    @app.exception_handler(500)
    async def internal_exception_handler():
        return JSONResponse(status_code=500, content=jsonable_encoder({"code": 500, "msg": "Internal Server Error"}))

    @app.exception_handler(400)
    async def bad_request_handler():
        return JSONResponse(status_code=400, content=jsonable_encoder({"code": 400, "msg": "Bad request"}))

    @app.exception_handler(RequestValidationError)
    async def request_validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = jsonable_encoder(exc.errors())
        status_code = (
            status.HTTP_400_BAD_REQUEST
            if __is_bad_request(errors)
            else status.HTTP_422_UNPROCESSABLE_ENTITY
        )
        return JSONResponse(
            status_code=status_code,
            content={"detail": errors},
        )


def __is_bad_request(errors: Sequence[Any]) -> bool:
    """Check if the given error indicates a malformed request."""
    if not len(errors) == 1:
        return False

    error_item = errors[0]

    if not isinstance(error_item, dict):
        return False

    if not isinstance(error_item.get("loc"), list):
        return False

    loc = error_item["loc"]

    if not 1 <= len(loc) <= 2:
        return False

    loc_item1 = loc[0]

    if loc_item1 != "body":
        return False

    loc_item2 = loc[1] if len(loc) > 1 else None

    if loc_item2:
        return False

    if not isinstance(error_item.get("msg"), str):
        return False

    msg = error_item["msg"]

    return (
            msg == "field required"
            or msg == "value is not a valid dict"
            or msg.startswith("Expecting value:")
    )