from nplg_mcp.errors import AppError, ErrorCode, to_public_error


def test_public_error_keeps_safe_context_and_redacts_internal_cause() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository did not return a valid item page.",
        http_status=502,
        safe_details={"handle": "1234/567"},
        internal_details={"upstream_body": "secret debug body"},
    )

    public = to_public_error(error)

    assert public == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository did not return a valid item page.",
        "details": {"handle": "1234/567"},
    }
    assert "secret" not in repr(public)


def test_unexpected_exception_becomes_stable_internal_error() -> None:
    public = to_public_error(RuntimeError("database password leaked"))

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }
