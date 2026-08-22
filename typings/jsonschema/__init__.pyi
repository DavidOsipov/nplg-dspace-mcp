# Copyright (c) 2026 David Osipov

from collections.abc import Iterator

from .exceptions import ValidationError

class FormatChecker:
    def __init__(self, formats: object = ...) -> None: ...

class Draft202012Validator:
    def __init__(
        self,
        schema: object,
        *,
        format_checker: FormatChecker | None = ...,
        registry: object | None = ...,
    ) -> None: ...
    @classmethod
    def check_schema(cls, schema: object) -> None: ...
    def iter_errors(self, instance: object) -> Iterator[ValidationError]: ...
    def validate(self, instance: object) -> None: ...
