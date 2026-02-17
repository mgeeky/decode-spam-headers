from __future__ import annotations

import importlib.util
from pathlib import Path

from app.engine.analyzer import HeaderAnalyzer
from app.engine.logger import Logger as EngineLogger
from app.engine.models import AnalysisRequest, TestStatus


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _load_legacy_module() -> object:
    legacy_path = Path(__file__).resolve().parents[3] / "decode-spam-headers.py"
    spec = importlib.util.spec_from_file_location(
        "legacy_decode_spam_headers", legacy_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load legacy decode-spam-headers module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _legacy_output(raw_headers: str) -> dict[str, dict[str, str]]:
    module = _load_legacy_module()
    module.options["dont_resolve"] = True
    module.options["nocolor"] = True
    module.options["format"] = "json"
    module.options["log"] = "none"
    module.options["debug"] = False
    module.options["verbose"] = False
    module.logger = module.Logger(module.options)

    base = module.SMTPHeadersAnalysis(module.logger, False, False, [], True)
    standard, decode_all, array_tests = base.getAllTests()
    max_test = max(int(test[0]) for test in (standard + decode_all + array_tests))
    tests_to_run = list(range(max_test + 5))

    analyzer = module.SMTPHeadersAnalysis(
        module.logger, False, False, tests_to_run, True
    )
    output = analyzer.parse(raw_headers)
    for payload in output.values():
        for key in ("header", "value", "analysis", "description"):
            if key in payload and isinstance(payload[key], str):
                payload[key] = EngineLogger.noColors(payload[key])
    return output


def _engine_output(raw_headers: str) -> dict[str, dict[str, str]]:
    analyzer = HeaderAnalyzer()
    result = analyzer.analyze(
        AnalysisRequest(
            headers=raw_headers,
            config={
                "resolve": False,
                "decode_all": False,
                "test_ids": [],
            },
        )
    )
    return {
        item.test_name: {
            "header": item.header_name,
            "value": item.header_value,
            "analysis": item.analysis,
            "description": item.description,
        }
        for item in result.results
        if item.status == TestStatus.success
    }


def test_engine_matches_legacy_cli_output_for_sample_headers() -> None:
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")
    assert _engine_output(raw_headers) == _legacy_output(raw_headers)
