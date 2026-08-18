# Copyright (c) 2026 David Osipov
"""Typed HTTP client seams for bounded upstream streaming."""

import collections.abc
import contextlib
from typing import Protocol


class HttpResponseProtocol(Protocol):
    """The response surface consumed by repository and downloader code."""

    @property
    def status_code(self) -> int:
        """Return the upstream HTTP status code."""
        ...

    @property
    def headers(self) -> collections.abc.Mapping[str, str]:
        """Return the response headers through their mapping surface."""
        ...

    @property
    def charset_encoding(self) -> str | None:
        """Return the declared or detected response character encoding."""
        ...

    def aiter_bytes(self) -> collections.abc.AsyncIterator[bytes]:
        """Iterate over decoded response-body chunks."""
        ...


class HttpClientProtocol(Protocol):
    """The no-redirect streaming surface required by the upstream clients."""

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: collections.abc.Mapping[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> contextlib.AbstractAsyncContextManager[HttpResponseProtocol]:
        """Open a no-redirect streaming response context."""
        ...

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        ...
