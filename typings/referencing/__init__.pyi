# Copyright (c) 2026 David Osipov

from collections.abc import Callable

class Resource[T]:
    @staticmethod
    def from_contents(contents: T) -> Resource[T]: ...

class Registry[T]:
    def __init__(
        self,
        *,
        retrieve: Callable[[str], Resource[T]],
    ) -> None: ...
    def with_resource(self, uri: str, resource: Resource[T]) -> Registry[T]: ...
