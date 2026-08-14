from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


class ErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    NOT_FOUND = "NOT_FOUND"
    RESTRICTED = "RESTRICTED"
    UPSTREAM_FAILURE = "UPSTREAM_FAILURE"
    DOWNLOAD_TOO_LARGE = "DOWNLOAD_TOO_LARGE"
    INVALID_DOCUMENT = "INVALID_DOCUMENT"
    PDF_PROCESSING_FAILED = "PDF_PROCESSING_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    CACHE_FULL = "CACHE_FULL"
    UNAUTHORIZED = "UNAUTHORIZED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(slots=True)
class AppError(Exception):
    code: ErrorCode
    message: str
    http_status: int = 400
    safe_details: Mapping[str, Any] | None = None
    internal_details: Mapping[str, Any] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)


def to_public_error(error: BaseException) -> dict[str, Any]:
    if isinstance(error, AppError):
        result: dict[str, Any] = {
            "code": error.code.value,
            "message": error.message,
        }
        if error.safe_details:
            result["details"] = dict(error.safe_details)
        return result
    return {
        "code": ErrorCode.INTERNAL_ERROR.value,
        "message": "The server could not complete the request.",
    }
