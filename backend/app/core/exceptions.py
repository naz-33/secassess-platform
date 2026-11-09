from typing import Any, Optional
from fastapi import HTTPException, status


class AppException(HTTPException):
    """Base exception for application errors."""
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: Any = None,
        headers: Optional[dict[str, str]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class NotFoundException(AppException):
    def __init__(self, resource: str, identifier: Any):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} with identifier '{identifier}' not found",
        )


class UnauthorizedException(AppException):
    def __init__(self, detail: str = "Invalid authentication credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class ForbiddenException(AppException):
    def __init__(self, detail: str = "Operation not permitted"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class ScopeViolationException(ForbiddenException):
    def __init__(self, asset: str, target_id: Any):
        super().__init__(
            detail=f"Asset '{asset}' is OUT OF SCOPE or unauthorized for target '{target_id}'"
        )


class ConflictException(AppException):
    def __init__(self, detail: str = "Resource conflict or invalid state transition"):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )


class PayloadTooLargeException(AppException):
    def __init__(self, detail: str = "Payload or file size exceeds maximum permitted limit"):
        super().__init__(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=detail,
        )


class UnsupportedMediaTypeException(AppException):
    def __init__(self, detail: str = "Unsupported media type or file format"):
        super().__init__(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=detail,
        )


class UnprocessableEntityException(AppException):
    def __init__(self, detail: str = "Unprocessable entity validation error"):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
        )


class RateLimitException(AppException):
    def __init__(self, detail: str = "AI rate limit or usage quota exceeded"):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
        )


class BadGatewayException(AppException):
    def __init__(self, detail: str = "AI provider returned an upstream error"):
        super().__init__(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=detail,
        )


class ServiceUnavailableException(AppException):
    def __init__(self, detail: str = "AI service temporarily unavailable or unconfigured"):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
        )
