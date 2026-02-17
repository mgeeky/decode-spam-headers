from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.parser import HeaderParser


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture()
def sample_headers() -> str:
    return (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")


def test_parser_extracts_headers_and_preserves_order(sample_headers: str) -> None:
    parser = HeaderParser()
    headers = parser.parse(sample_headers)

    assert headers, "Expected parsed headers to be non-empty."

    indices = [header.index for header in headers]
    assert indices == list(range(len(headers)))

    names = [header.name for header in headers]
    assert names[:2] == ["Received", "Received"]
    assert "X-Should-Not-Be-Parsed" not in names


def test_parser_handles_folded_lines(sample_headers: str) -> None:
    parser = HeaderParser()
    headers = parser.parse(sample_headers)

    subject = next(header for header in headers if header.name == "Subject")
    assert "folded line" in subject.value
    assert "\n" in subject.value

    authentication = next(
        header for header in headers if header.name == "Authentication-Results"
    )
    assert "spf=pass" in authentication.value
    assert "\n" in authentication.value


def test_parser_preserves_content_type_boundary(sample_headers: str) -> None:
    parser = HeaderParser()
    headers = parser.parse(sample_headers)

    content_type = next(header for header in headers if header.name == "Content-Type")
    assert "boundary=\"boundary-123\"" in content_type.value