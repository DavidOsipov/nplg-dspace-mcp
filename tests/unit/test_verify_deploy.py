from __future__ import annotations

import pytest

from scripts.verify_deploy import (
    CACHE_WRITING_TOOLS,
    EXPECTED_TOOLS,
    VerificationError,
    verify,
)


class FakeClient:
    def __init__(self, *, read_only: bool | None) -> None:
        self.read_only = read_only

    def get(self, path: str):
        return {"status": "ok"} if path == "/healthz" else {"status": "ready"}

    def rpc(self, method: str, params=None, *, name=None):
        headers = {}
        if method == "server/discover":
            return {"supportedVersions": ["2026-07-28"], "cacheScope": "private"}, headers
        if method == "tools/list":
            tools = [
                {
                    "name": tool_name,
                    "annotations": {
                        "readOnlyHint": (
                            tool_name not in CACHE_WRITING_TOOLS if self.read_only is None else self.read_only
                        ),
                        "destructiveHint": False,
                    },
                }
                for tool_name in sorted(EXPECTED_TOOLS)
            ]
            return {"tools": tools, "cacheScope": "private"}, headers
        if method == "resources/list":
            return {"resources": [{"uri": "nplg://about"}]}, headers
        if method == "resources/read":
            return {"contents": [{"uri": "nplg://about"}]}, headers
        raise AssertionError(method)


def test_deployment_verifier_accepts_truthful_cache_write_annotations() -> None:
    assert verify(FakeClient(read_only=None))["status"] == "pass"


def test_deployment_verifier_rejects_misclassified_tool_catalog() -> None:
    with pytest.raises(VerificationError, match="annotation mismatch"):
        verify(FakeClient(read_only=False))
