from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
from typing import Iterable

from app.engine.logger import Logger as EngineLogger
from app.engine.models import Severity, TestResult, TestStatus
from app.engine.parser import ParsedHeader


_LEGACY_MODULE = None
_TEST_CATALOG: dict[int, tuple[str, str]] | None = None
_ARRAY_TESTS: set[int] | None = None
_BASE_HANDLED: list[str] | None = None
_BASE_APPLIANCES: set[str] | None = None
_CONTEXT_SIGNATURE: tuple[tuple[str, str], ...] | None = None
_CONTEXT_CONFIG: tuple[bool, bool, bool] | None = None
_CONTEXT_ANALYSIS = None

_LEGACY_CONFIG = {
    "resolve": False,
    "decode_all": False,
    "include_unusual": True,
}


def configure_legacy(
    *, resolve: bool, decode_all: bool, include_unusual: bool = True
) -> None:
    _LEGACY_CONFIG["resolve"] = bool(resolve)
    _LEGACY_CONFIG["decode_all"] = bool(decode_all)
    _LEGACY_CONFIG["include_unusual"] = bool(include_unusual)


def _load_legacy_module() -> object:
    global _LEGACY_MODULE
    if _LEGACY_MODULE is not None:
        return _LEGACY_MODULE

    root = Path(__file__).resolve().parents[4]
    legacy_path = root / "decode-spam-headers.py"
    if not legacy_path.exists():
        raise FileNotFoundError(f"Missing legacy analyzer at {legacy_path}")

    spec = importlib.util.spec_from_file_location(
        "legacy_decode_spam_headers", legacy_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load legacy decode-spam-headers module.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    _apply_legacy_options(module)

    _LEGACY_MODULE = module
    return module


def _load_test_catalog() -> tuple[dict[int, tuple[str, str]], set[int]]:
    global _TEST_CATALOG, _ARRAY_TESTS, _BASE_HANDLED, _BASE_APPLIANCES
    if _TEST_CATALOG is not None and _ARRAY_TESTS is not None:
        return _TEST_CATALOG, _ARRAY_TESTS

    module = _load_legacy_module()
    analyzer = module.SMTPHeadersAnalysis(module.logger)
    standard, decode_all, array_tests = analyzer.getAllTests()

    catalog: dict[int, tuple[str, str]] = {}
    array_ids: set[int] = set()

    for test_id, name, func in standard + decode_all + array_tests:
        catalog[int(test_id)] = (name, func.__name__)
    for test_id, _name, _func in array_tests:
        array_ids.add(int(test_id))

    if 35 not in catalog and hasattr(analyzer, "testTLCOObClasifiers"):
        catalog[35] = ("X-MS-Oob-TLC-OOBClassifiers", "testTLCOObClasifiers")

    _BASE_HANDLED = list(module.SMTPHeadersAnalysis.Handled_Spam_Headers)
    _BASE_APPLIANCES = set(module.SMTPHeadersAnalysis.Manually_Added_Appliances)
    _TEST_CATALOG = catalog
    _ARRAY_TESTS = array_ids
    return catalog, array_ids


def _apply_legacy_options(module: object) -> None:
    options = getattr(module, "options", None)
    if isinstance(options, dict):
        options["dont_resolve"] = not _LEGACY_CONFIG["resolve"]
        options["nocolor"] = True
        options["format"] = "json"
        options["log"] = "none"
        options["debug"] = False
        options["verbose"] = False

    try:
        module.logger.options["log"] = "none"
        module.logger.options["nocolor"] = True
        module.logger.options["format"] = "json"
        module.logger.options["debug"] = False
        module.logger.options["verbose"] = False
    except Exception:
        pass


def _reset_legacy_state(module: object) -> None:
    if _BASE_HANDLED is not None:
        module.SMTPHeadersAnalysis.Handled_Spam_Headers = list(_BASE_HANDLED)
    if _BASE_APPLIANCES is not None:
        module.SMTPHeadersAnalysis.Manually_Added_Appliances = set(_BASE_APPLIANCES)


def _headers_signature(headers: list[ParsedHeader]) -> tuple[tuple[str, str], ...]:
    return tuple((header.name, header.value) for header in headers)


def _build_text(headers: list[ParsedHeader]) -> str:
    lines: list[str] = []
    for header in headers:
        if header.value:
            lines.append(f"{header.name}: {header.value}")
        else:
            lines.append(f"{header.name}:")
    return "\n".join(lines)


def _get_analysis(headers: list[ParsedHeader]) -> object:
    global _CONTEXT_SIGNATURE, _CONTEXT_ANALYSIS, _CONTEXT_CONFIG
    module = _load_legacy_module()
    catalog, _array_ids = _load_test_catalog()
    _apply_legacy_options(module)

    tests_to_run = sorted(catalog.keys())
    config_signature = (
        _LEGACY_CONFIG["resolve"],
        _LEGACY_CONFIG["decode_all"],
        _LEGACY_CONFIG["include_unusual"],
    )

    signature = _headers_signature(headers)
    if (
        _CONTEXT_ANALYSIS is None
        or _CONTEXT_SIGNATURE != signature
        or _CONTEXT_CONFIG != config_signature
    ):
        _reset_legacy_state(module)
        analyzer = module.SMTPHeadersAnalysis(
            module.logger,
            resolve=_LEGACY_CONFIG["resolve"],
            decode_all=_LEGACY_CONFIG["decode_all"],
            testsToRun=tests_to_run,
            includeUnusual=_LEGACY_CONFIG["include_unusual"],
        )
        analyzer.headers = [(h.index, h.name, h.value) for h in headers]
        analyzer.text = _build_text(headers)
        _apply_legacy_options(module)
        _CONTEXT_SIGNATURE = signature
        _CONTEXT_CONFIG = config_signature
        _CONTEXT_ANALYSIS = analyzer
    return _CONTEXT_ANALYSIS


def _strip_colors(value: str) -> str:
    if not value:
        return ""
    try:
        return EngineLogger.noColors(str(value))
    except Exception:
        return str(value)


def _normalize_payload(payload: object) -> tuple[str, str, str, str] | None:
    if isinstance(payload, dict):
        header = payload.get("header", "")
        value = payload.get("value", "")
        analysis = payload.get("analysis", "")
        description = payload.get("description", "")
        return (
            str(header) if header is not None else "",
            str(value) if value is not None else "",
            str(analysis) if analysis is not None else "",
            str(description) if description is not None else "",
        )
    if isinstance(payload, str):
        return ("-", "-", payload, "")
    return None


def _combine_payloads(payloads: list[tuple[str, str, str, str]]) -> tuple[str, str, str, str]:
    headers: list[str] = []
    values: list[str] = []
    analyses: list[str] = []
    descriptions: list[str] = []
    saw_header_dash = False
    saw_value_dash = False
    saw_header_empty = False
    saw_value_empty = False

    for header, value, analysis, description in payloads:
        if header == "-":
            saw_header_dash = True
        elif header:
            headers.append(header)
        else:
            saw_header_empty = True

        if value == "-":
            saw_value_dash = True
        elif value:
            values.append(value)
        else:
            saw_value_empty = True

        if analysis:
            analyses.append(analysis)
        if description:
            descriptions.append(description)

    if headers:
        header_name = ", ".join(dict.fromkeys(headers))
    elif saw_header_dash:
        header_name = "-"
    elif saw_header_empty:
        header_name = ""
    else:
        header_name = "-"

    if values:
        header_value = "\n".join(values)
    elif saw_value_dash:
        header_value = "-"
    elif saw_value_empty:
        header_value = ""
    else:
        header_value = "-"

    analysis = "\n\n".join(analyses)
    description = "\n\n".join(descriptions)
    return header_name, header_value, analysis, description


@dataclass
class LegacyScanner:
    id: int
    name: str
    method_name: str
    category: str | None = None

    def run(self, headers: list[ParsedHeader]) -> TestResult | None:
        analyzer = _get_analysis(headers)
        if not hasattr(analyzer, self.method_name):
            return None
        result = getattr(analyzer, self.method_name)()
        if not result:
            return None

        payloads: list[tuple[str, str, str, str]] = []
        if isinstance(result, list | tuple):
            for item in result:
                normalized = _normalize_payload(item)
                if normalized:
                    payloads.append(normalized)
        else:
            normalized = _normalize_payload(result)
            if normalized:
                payloads.append(normalized)

        if not payloads:
            return None

        header_name, header_value, analysis, description = _combine_payloads(payloads)
        return TestResult(
            test_id=self.id,
            test_name=self.name,
            header_name=_strip_colors(header_name),
            header_value=_strip_colors(header_value),
            analysis=_strip_colors(analysis),
            description=_strip_colors(description),
            severity=Severity.info,
            status=TestStatus.success,
        )


def build_scanners(test_ids: Iterable[int], category: str | None = None) -> list[LegacyScanner]:
    catalog, _array_ids = _load_test_catalog()
    scanners: list[LegacyScanner] = []
    for test_id in test_ids:
        if test_id not in catalog:
            raise ValueError(f"Unknown test id: {test_id}")
        name, method_name = catalog[test_id]
        scanners.append(
            LegacyScanner(id=test_id, name=name, method_name=method_name, category=category)
        )
    return scanners
