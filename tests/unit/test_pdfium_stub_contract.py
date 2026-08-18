# Copyright (c) 2026 David Osipov
"""Verify the local PDFium types against the exact pinned runtime wheel."""

from __future__ import annotations

import ast
import inspect
import io
import tokenize
from collections.abc import Buffer, Iterator, Sequence
from importlib.metadata import version
from pathlib import Path
from typing import Final, cast

import pypdfium2 as pdfium
import pytest
from PIL.Image import Image
from pypdfium2 import raw as pdfium_c

from tests.helpers.pdf_factory import make_raster_pdf

_PINNED_PYPDFIUM_VERSION: Final = "5.8.0"
_RASTER_WIDTH: Final = 64
_RASTER_HEIGHT: Final = 48
_STUB_ROOT: Final = Path(__file__).parents[2] / "typings" / "pypdfium2"
_REPOSITORY_ROOT: Final = Path(__file__).parents[2]
_TASK6A_TYPED_PATHS: Final = (
    Path("src/nplg_mcp/storage.py"),
    Path("src/nplg_mcp/pdf.py"),
    Path("tests/integration/test_pdf.py"),
    Path("tests/unit/test_storage.py"),
    Path("tests/unit/test_tiles.py"),
    Path("tests/helpers/pdf_factory.py"),
    Path("tests/unit/test_pdfium_stub_contract.py"),
    Path("typings/pypdfium2/__init__.pyi"),
    Path("typings/pypdfium2/raw.pyi"),
)
_SUPPRESSION_MARKERS: Final = (
    "noqa",
    "type: ignore",
    "pyright: ignore",
    "mypy:",
    "nosec",
    "nosemgrep",
    "fmt: off",
    "fmt: skip",
    "yapf: disable",
    "black: skip",
)
_PDF_CONSTRUCTOR_RATIONALE: Final = (
    "    # app.py, app_factory.py, test_pdf.py, and delete_render.py depend on this",
    "    # explicit keyword contract; a limits bundle crosses Task 6A/6C boundaries.",
)
_VENDOR_PREFIX: Final = "        # pypdfium2 5.8.0 exposes"
_FILTER_RATIONALE: Final = (
    f"{_VENDOR_PREFIX} `filter`; renaming it would break keyword parity.",
)
_INPUT_RATIONALE: Final = (
    f"{_VENDOR_PREFIX} `input`; renaming it would break keyword parity.",
)
type _AuthorizedSuppression = tuple[
    Path,
    tuple[str, str, str | None],
    str,
    tuple[str, ...],
]
_AUTHORIZED_SUPPRESSIONS: Final[tuple[_AuthorizedSuppression, ...]] = (
    (
        Path("src/nplg_mcp/pdf.py"),
        ("PdfProcessor", "__init__", None),
        "# noqa: PLR0913",
        _PDF_CONSTRUCTOR_RATIONALE,
    ),
    (
        Path("typings/pypdfium2/__init__.pyi"),
        ("PdfPage", "get_objects", "filter"),
        "# noqa: A002",
        _FILTER_RATIONALE,
    ),
    (
        Path("typings/pypdfium2/__init__.pyi"),
        ("PdfDocument", "__init__", "input"),
        "# noqa: A002",
        _INPUT_RATIONALE,
    ),
)
_PUBLIC_STUB_SYMBOLS: Final = frozenset(
    {
        "PDFIUM_INFO",
        "PYPDFIUM_INFO",
        "PdfBitmap",
        "PdfDocument",
        "PdfImage",
        "PdfObject",
        "PdfPage",
        "PdfTextPage",
        "PdfiumError",
    }
)
_PUBLIC_RAW_SYMBOLS: Final = frozenset({"FPDF_PAGEOBJ_IMAGE", "FPDF_PAGEOBJ_TEXT"})
_PUBLIC_METHODS: Final[dict[str, frozenset[str]]] = {
    "PdfiumError": frozenset(),
    "PdfBitmap": frozenset({"to_pil", "close"}),
    "PdfTextPage": frozenset({"count_chars", "get_text_range", "close"}),
    "PdfObject": frozenset({"get_bounds", "close"}),
    "PdfImage": frozenset({"get_px_size", "get_filters", "get_data", "get_bitmap"}),
    "PdfPage": frozenset(
        {
            "get_size",
            "get_cropbox",
            "get_mediabox",
            "get_rotation",
            "get_objects",
            "get_textpage",
            "render",
            "close",
        }
    ),
    "PdfDocument": frozenset(
        {"__init__", "__len__", "__getitem__", "close", "__enter__", "__exit__"}
    ),
}
_RETURN_ANNOTATIONS: Final[dict[tuple[str, str], str]] = {
    ("PdfBitmap", "to_pil"): "Image",
    ("PdfBitmap", "close"): "bool",
    ("PdfTextPage", "count_chars"): "int",
    ("PdfTextPage", "get_text_range"): "str",
    ("PdfTextPage", "close"): "bool",
    ("PdfObject", "get_bounds"): "tuple[float, float, float, float]",
    ("PdfObject", "close"): "bool",
    ("PdfImage", "get_px_size"): "tuple[int, int]",
    ("PdfImage", "get_filters"): "list[str]",
    ("PdfImage", "get_data"): "Buffer",
    ("PdfImage", "get_bitmap"): "PdfBitmap",
    ("PdfPage", "get_size"): "tuple[float, float]",
    ("PdfPage", "get_cropbox"): "tuple[float, float, float, float]",
    ("PdfPage", "get_mediabox"): "tuple[float, float, float, float]",
    ("PdfPage", "get_rotation"): "int",
    ("PdfPage", "get_objects"): "Iterator[PdfObject]",
    ("PdfPage", "get_textpage"): "PdfTextPage",
    ("PdfPage", "render"): "PdfBitmap",
    ("PdfPage", "close"): "bool",
    ("PdfDocument", "__init__"): "None",
    ("PdfDocument", "__len__"): "int",
    ("PdfDocument", "__getitem__"): "PdfPage",
    ("PdfDocument", "close"): "bool",
    ("PdfDocument", "__enter__"): "Self",
    ("PdfDocument", "__exit__"): "None",
}
type _CallableKey = tuple[str, str]
type _ParameterContract = tuple[tuple[str, str, str], ...]
_REQUIRED_PARAMETER: Final = "<required>"
_BITMAP_MAKER_PARAMETER: Final = ("PdfPage", "render", "bitmap_maker")
_BITMAP_MAKER_RUNTIME_DEFAULT_REPR: Final = (
    "<bound method PdfBitmap.new_native of "
    "<class 'pypdfium2._helpers.bitmap.PdfBitmap'>>"
)
_BITMAP_MAKER_STUB_DEFAULT: Final = "..."


def _required_parameter_probe(_value: object) -> None:
    pass


_EMPTY_PARAMETER_DEFAULT: Final[object] = cast(
    "object",
    inspect.signature(_required_parameter_probe).parameters["_value"].default,
)


def _stub_tree(filename: str) -> ast.Module:
    return ast.parse((_STUB_ROOT / filename).read_text(encoding="utf-8"))


def _public_symbols(tree: ast.Module) -> frozenset[str]:
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            symbols.add(node.name)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and not node.target.id.startswith("_")
        ):
            symbols.add(node.target.id)
    return frozenset(symbols)


def _classes(tree: ast.Module) -> dict[str, ast.ClassDef]:
    return {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}


def _methods(node: ast.ClassDef) -> dict[str, ast.FunctionDef]:
    return {
        child.name: child for child in node.body if isinstance(child, ast.FunctionDef)
    }


def _stub_parameter_contract(function: ast.FunctionDef) -> _ParameterContract:
    positional = (*function.args.posonlyargs, *function.args.args)
    first_default = len(positional) - len(function.args.defaults)
    contract: list[tuple[str, str, str]] = []
    for index, argument in enumerate(positional):
        kind = (
            "POSITIONAL_ONLY"
            if index < len(function.args.posonlyargs)
            else "POSITIONAL_OR_KEYWORD"
        )
        default = (
            _REQUIRED_PARAMETER
            if index < first_default
            else ast.unparse(function.args.defaults[index - first_default])
        )
        contract.append((argument.arg, kind, default))
    if function.args.vararg is not None:
        contract.append(
            (function.args.vararg.arg, "VAR_POSITIONAL", _REQUIRED_PARAMETER)
        )
    for argument, default_node in zip(
        function.args.kwonlyargs, function.args.kw_defaults, strict=True
    ):
        default = (
            _REQUIRED_PARAMETER if default_node is None else ast.unparse(default_node)
        )
        contract.append((argument.arg, "KEYWORD_ONLY", default))
    if function.args.kwarg is not None:
        contract.append((function.args.kwarg.arg, "VAR_KEYWORD", _REQUIRED_PARAMETER))
    return tuple(contract)


def _runtime_parameter_contract(
    signature: inspect.Signature,
    callable_key: _CallableKey,
) -> _ParameterContract:
    contract: list[tuple[str, str, str]] = []
    for parameter in signature.parameters.values():
        default = cast("object", parameter.default)
        if default is _EMPTY_PARAMETER_DEFAULT:
            default_text = _REQUIRED_PARAMETER
        elif (*callable_key, parameter.name) == _BITMAP_MAKER_PARAMETER:
            assert callable(default)
            assert repr(default) == _BITMAP_MAKER_RUNTIME_DEFAULT_REPR
            default_text = _BITMAP_MAKER_STUB_DEFAULT
        else:
            default_text = repr(default)
        contract.append((parameter.name, parameter.kind.name, default_text))
    return tuple(contract)


def _suppression_comments(path: Path) -> tuple[tuple[int, str], ...]:
    source = path.read_text(encoding="utf-8")
    return tuple(
        (token.start[0], token.string)
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT
        and any(marker in token.string.casefold() for marker in _SUPPRESSION_MARKERS)
    )


def _suppression_owner_at_line(
    path: Path, line_number: int
) -> tuple[str, str, str | None]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    method_matches = tuple(
        (class_node.name, method.name, None)
        for class_node in tree.body
        if isinstance(class_node, ast.ClassDef)
        for method in class_node.body
        if isinstance(method, ast.FunctionDef) and method.lineno == line_number
    )
    parameter_matches = tuple(
        (class_node.name, method.name, argument.arg)
        for class_node in tree.body
        if isinstance(class_node, ast.ClassDef)
        for method in class_node.body
        if isinstance(method, ast.FunctionDef)
        for argument in (
            *method.args.posonlyargs,
            *method.args.args,
            *method.args.kwonlyargs,
        )
        if argument.lineno == line_number
    )
    matches = (*method_matches, *parameter_matches)
    assert len(matches) == 1
    return matches[0]


def _runtime_signatures() -> dict[_CallableKey, inspect.Signature]:
    assert version("pypdfium2") == _PINNED_PYPDFIUM_VERSION
    return {
        ("PdfBitmap", "to_pil"): inspect.signature(pdfium.PdfBitmap.to_pil),
        ("PdfBitmap", "close"): inspect.signature(pdfium.PdfBitmap.close),
        ("PdfTextPage", "count_chars"): inspect.signature(
            pdfium.PdfTextPage.count_chars
        ),
        ("PdfTextPage", "get_text_range"): inspect.signature(
            pdfium.PdfTextPage.get_text_range
        ),
        ("PdfTextPage", "close"): inspect.signature(pdfium.PdfTextPage.close),
        ("PdfObject", "get_bounds"): inspect.signature(pdfium.PdfObject.get_bounds),
        ("PdfObject", "close"): inspect.signature(pdfium.PdfObject.close),
        ("PdfImage", "get_px_size"): inspect.signature(pdfium.PdfImage.get_px_size),
        ("PdfImage", "get_filters"): inspect.signature(pdfium.PdfImage.get_filters),
        ("PdfImage", "get_data"): inspect.signature(pdfium.PdfImage.get_data),
        ("PdfImage", "get_bitmap"): inspect.signature(pdfium.PdfImage.get_bitmap),
        ("PdfPage", "get_size"): inspect.signature(pdfium.PdfPage.get_size),
        ("PdfPage", "get_cropbox"): inspect.signature(pdfium.PdfPage.get_cropbox),
        ("PdfPage", "get_mediabox"): inspect.signature(pdfium.PdfPage.get_mediabox),
        ("PdfPage", "get_rotation"): inspect.signature(pdfium.PdfPage.get_rotation),
        ("PdfPage", "get_objects"): inspect.signature(pdfium.PdfPage.get_objects),
        ("PdfPage", "get_textpage"): inspect.signature(pdfium.PdfPage.get_textpage),
        ("PdfPage", "render"): inspect.signature(pdfium.PdfPage.render),
        ("PdfPage", "close"): inspect.signature(pdfium.PdfPage.close),
        ("PdfDocument", "__init__"): inspect.signature(pdfium.PdfDocument.__init__),
        ("PdfDocument", "__len__"): inspect.signature(pdfium.PdfDocument.__len__),
        ("PdfDocument", "__getitem__"): inspect.signature(
            pdfium.PdfDocument.__getitem__
        ),
        ("PdfDocument", "close"): inspect.signature(pdfium.PdfDocument.close),
        ("PdfDocument", "__enter__"): inspect.signature(pdfium.PdfDocument.__enter__),
        ("PdfDocument", "__exit__"): inspect.signature(pdfium.PdfDocument.__exit__),
    }


def _assert_stub_callable_contracts_match_runtime(tree: ast.Module) -> None:
    classes = _classes(tree)
    runtime_signatures = _runtime_signatures()

    for class_name, expected_names in _PUBLIC_METHODS.items():
        class_node = classes.get(class_name)
        assert class_node is not None, f"stub class is missing: {class_name}"
        methods = _methods(class_node)
        assert frozenset(methods) == expected_names
        for method_name in expected_names:
            method = methods[method_name]
            key = (class_name, method_name)
            assert _stub_parameter_contract(method) == _runtime_parameter_contract(
                runtime_signatures[key], key
            ), f"{class_name}.{method_name} parameter contract differs from runtime"
            assert method.returns is not None
            assert ast.unparse(method.returns) == _RETURN_ANNOTATIONS[key]


def test_stub_declares_only_real_pdfium_symbols_used_by_the_adapter() -> None:
    init_tree = _stub_tree("__init__.pyi")
    raw_tree = _stub_tree("raw.pyi")

    assert _public_symbols(init_tree) == _PUBLIC_STUB_SYMBOLS
    assert _public_symbols(raw_tree) == _PUBLIC_RAW_SYMBOLS
    assert version("pypdfium2") == _PINNED_PYPDFIUM_VERSION
    assert not hasattr(pdfium, "PdfPageObject")


def test_task6a_has_only_the_authorized_compatibility_suppression() -> None:
    suppressions = tuple(
        (relative_path, line_number, comment)
        for relative_path in _TASK6A_TYPED_PATHS
        for line_number, comment in _suppression_comments(
            _REPOSITORY_ROOT / relative_path
        )
    )

    assert len(suppressions) == len(_AUTHORIZED_SUPPRESSIONS)
    for observed, expected in zip(suppressions, _AUTHORIZED_SUPPRESSIONS, strict=True):
        relative_path, line_number, comment = observed
        expected_path, expected_owner, expected_comment, expected_rationale = expected
        path = _REPOSITORY_ROOT / relative_path
        assert relative_path == expected_path
        assert comment == expected_comment
        assert _suppression_owner_at_line(path, line_number) == expected_owner
        source_lines = path.read_text(encoding="utf-8").splitlines()
        rationale_start = line_number - 1 - len(expected_rationale)
        assert tuple(source_lines[rationale_start : line_number - 1]) == (
            expected_rationale
        )


def test_stub_callable_shapes_and_return_protocols_match_runtime() -> None:
    _assert_stub_callable_contracts_match_runtime(_stub_tree("__init__.pyi"))


def test_callable_contract_rejects_non_targeted_default_mutant() -> None:
    tree = _stub_tree("__init__.pyi")
    method = _methods(_classes(tree)["PdfTextPage"])["get_text_range"]
    method.args.defaults[1] = ast.Constant(value=0)

    with pytest.raises(
        AssertionError,
        match=r"PdfTextPage\.get_text_range parameter contract differs from runtime",
    ):
        _assert_stub_callable_contracts_match_runtime(tree)


def test_pdf_document_constructor_parameters_and_defaults_match_runtime() -> None:
    expected = (
        ("self", "POSITIONAL_OR_KEYWORD", _REQUIRED_PARAMETER),
        ("input", "POSITIONAL_OR_KEYWORD", _REQUIRED_PARAMETER),
        ("password", "POSITIONAL_OR_KEYWORD", "None"),
        ("autoclose", "POSITIONAL_OR_KEYWORD", "False"),
    )
    method = _methods(_classes(_stub_tree("__init__.pyi"))["PdfDocument"])["__init__"]

    assert (
        _runtime_parameter_contract(
            inspect.signature(pdfium.PdfDocument.__init__),
            ("PdfDocument", "__init__"),
        )
        == expected
    )
    assert _stub_parameter_contract(method) == expected


def test_pdf_page_get_objects_parameters_and_defaults_match_runtime() -> None:
    expected = (
        ("self", "POSITIONAL_OR_KEYWORD", _REQUIRED_PARAMETER),
        ("filter", "POSITIONAL_OR_KEYWORD", "None"),
        ("max_depth", "POSITIONAL_OR_KEYWORD", "15"),
        ("form", "POSITIONAL_OR_KEYWORD", "None"),
        ("level", "POSITIONAL_OR_KEYWORD", "0"),
        ("textpage", "POSITIONAL_OR_KEYWORD", "None"),
    )
    method = _methods(_classes(_stub_tree("__init__.pyi"))["PdfPage"])["get_objects"]

    assert (
        _runtime_parameter_contract(
            inspect.signature(pdfium.PdfPage.get_objects),
            ("PdfPage", "get_objects"),
        )
        == expected
    )
    assert _stub_parameter_contract(method) == expected


def test_runtime_page_object_iteration_and_image_protocols(tmp_path: Path) -> None:
    source = make_raster_pdf(
        tmp_path / "pdfium-contract.pdf",
        width=_RASTER_WIDTH,
        height=_RASTER_HEIGHT,
    )
    document = pdfium.PdfDocument(source.path)
    page = document[0]
    objects = page.get_objects()

    assert isinstance(objects, Iterator)
    assert not isinstance(objects, Sequence)
    page_objects = tuple(objects)
    images = tuple(
        page_object
        for page_object in page_objects
        if isinstance(page_object, pdfium.PdfImage)
    )
    assert images
    image = images[0]
    assert isinstance(image, pdfium.PdfObject)
    assert type(image.type) is int
    assert isinstance(image.get_bounds(), tuple)
    assert image.get_px_size() == (_RASTER_WIDTH, _RASTER_HEIGHT)
    filters = image.get_filters()
    assert isinstance(filters, list)
    assert all(isinstance(value, str) for value in filters)
    data = image.get_data(decode_simple=True)
    assert isinstance(data, Buffer)
    assert not isinstance(data, bytes)
    assert bytes(data)

    bitmap = image.get_bitmap(render=False)
    assert bitmap.width == _RASTER_WIDTH
    assert bitmap.height == _RASTER_HEIGHT
    assert isinstance(bitmap.to_pil(), Image)
    assert type(bitmap.close()) is bool

    text_page = page.get_textpage()
    assert type(text_page.count_chars()) is int
    assert isinstance(text_page.get_text_range(), str)
    assert type(text_page.close()) is bool

    rendered = page.render(
        scale=1.0,
        rev_byteorder=True,
        fill_color=(255, 255, 255, 255),
        draw_annots=True,
    )
    assert rendered.width > 0
    assert rendered.height > 0
    assert isinstance(rendered.to_pil(), Image)
    assert type(rendered.close()) is bool
    assert type(image.close()) is bool
    assert type(page.close()) is bool
    assert type(document.close()) is bool


def test_runtime_context_and_error_contract(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "pdfium-context.pdf")

    with pdfium.PdfDocument(source.path) as document:
        assert isinstance(document, pdfium.PdfDocument)

    assert not hasattr(pdfium.PdfPage, "__enter__")
    assert not hasattr(pdfium.PdfBitmap, "__enter__")
    assert not hasattr(pdfium.PdfObject, "__enter__")
    with pytest.raises(pdfium.PdfiumError):
        _ = pdfium.PdfDocument(b"not a PDF")


def test_raw_page_object_constants_are_plain_integers() -> None:
    assert type(pdfium_c.FPDF_PAGEOBJ_TEXT) is int
    assert type(pdfium_c.FPDF_PAGEOBJ_IMAGE) is int
