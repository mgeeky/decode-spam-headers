from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    spam = "spam"
    suspicious = "suspicious"
    clean = "clean"
    info = "info"


class TestStatus(StrEnum):
    success = "success"
    error = "error"
    skipped = "skipped"


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.spam: "#ff5555",
    Severity.suspicious: "#ffb86c",
    Severity.clean: "#50fa7b",
    Severity.info: "#bd93f9",
}


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    test_ids: list[int] = Field(
        default_factory=list,
        alias="testIds",
        description="Subset of test IDs to run. Empty means run all tests.",
    )
    resolve: bool = Field(
        default=False,
        description="Enable DNS resolution for supported checks.",
    )
    decode_all: bool = Field(
        default=False,
        alias="decodeAll",
        description="Decode opaque encoded values where possible.",
    )


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    headers: str = Field(
        min_length=1,
        max_length=1_048_576,
        description="Raw SMTP/IMAP header text supplied by the user.",
    )
    config: AnalysisConfig = Field(default_factory=AnalysisConfig)


class Test(BaseModel):
    id: int = Field(ge=1, description="Unique test identifier.")
    name: str = Field(min_length=1, description="Human-readable test name.")
    category: str = Field(min_length=1, description="Vendor/group category.")


class TestResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    test_id: int = Field(alias="testId")
    test_name: str = Field(alias="testName")
    header_name: str = Field(alias="headerName")
    header_value: str = Field(alias="headerValue")
    analysis: str
    description: str
    severity: Severity
    status: TestStatus
    error: str | None = None


class HopChainNode(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    index: int
    hostname: str
    ip: str | None = None
    timestamp: datetime | None = None
    server_info: str | None = Field(default=None, alias="serverInfo")
    delay: float | None = None


class SecurityAppliance(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    vendor: str
    headers: list[str]


class ReportMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_tests: int = Field(default=0, alias="totalTests")
    passed_tests: int = Field(default=0, alias="passedTests")
    failed_tests: int = Field(default=0, alias="failedTests")
    skipped_tests: int = Field(default=0, alias="skippedTests")
    elapsed_ms: float = Field(default=0.0, alias="elapsedMs")
    timed_out: bool = Field(default=False, alias="timedOut")
    incomplete_tests: list[str] = Field(default_factory=list, alias="incompleteTests")


class AnalysisResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    results: list[TestResult] = Field(default_factory=list)
    hop_chain: list[HopChainNode] = Field(default_factory=list, alias="hopChain")
    security_appliances: list[SecurityAppliance] = Field(
        default_factory=list, alias="securityAppliances"
    )
    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
