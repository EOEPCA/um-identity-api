from fastapi import status, APIRouter

from app.models.base import APIBaseModel

router = APIRouter(
    prefix="/health",
    tags=["Health checks"]
)


class HealthCheck(APIBaseModel):
    """Response model to validate and return when performing a health check."""
    status: str = "OK"


@router.get(
    "/liveness",
    summary="Perform a liveness Health Check",
    response_description="Return HTTP Status Code 200 (OK)",
    status_code=status.HTTP_200_OK
)
@router.get(
    "/readiness",
    summary="Perform a readiness Health Check",
    response_description="Return HTTP Status Code 200 (OK)",
    status_code=status.HTTP_200_OK
)
def get_health() -> HealthCheck:
    """
    ## Perform a Health Check
    Endpoint to perform a healthcheck on. This endpoint can primarily be used Docker
    to ensure a robust container orchestration and management is in place. Other
    services which rely on proper functioning of the API service will not deploy if this
    endpoint returns any other HTTP status code except 200 (OK).
    Returns:
        HealthCheck: Returns a JSON response with the health status
    """
    return HealthCheck(status="OK")