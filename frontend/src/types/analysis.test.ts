import { describe, expectTypeOf, it } from "vitest";

import type {
  AnalysisConfig,
  AnalysisProgress,
  AnalysisReport,
  HeaderInput,
  TestResult,
} from "./analysis";

describe("analysis types", () => {
  it("matches expected analysis config shape", () => {
    expectTypeOf<AnalysisConfig>().toEqualTypeOf<{
      testIds: number[];
      resolve: boolean;
      decodeAll: boolean;
    }>();
  });

  it("matches expected header input shape", () => {
    expectTypeOf<HeaderInput>().toEqualTypeOf<{
      rawText: string;
      source: "paste" | "file";
      fileName?: string;
    }>();
  });

  it("matches expected test result shape", () => {
    expectTypeOf<TestResult>().toEqualTypeOf<{
      testId: number;
      testName: string;
      headerName: string;
      headerValue: string;
      analysis: string;
      description: string;
      severity: "spam" | "suspicious" | "clean" | "info";
      status: "success" | "error" | "skipped";
      error?: string | null;
    }>();
  });

  it("matches expected report shape", () => {
    expectTypeOf<AnalysisReport>().toEqualTypeOf<{
      results: TestResult[];
      hopChain: {
        index: number;
        hostname: string;
        ip?: string;
        timestamp?: string;
        serverInfo?: string;
        delay?: number | null;
      }[];
      securityAppliances: {
        name: string;
        vendor: string;
        headers: string[];
      }[];
      metadata: {
        totalTests: number;
        passedTests: number;
        failedTests: number;
        skippedTests: number;
        elapsedMs: number;
        timedOut: boolean;
        incompleteTests: string[];
      };
    }>();
  });

  it("matches expected progress shape", () => {
    expectTypeOf<AnalysisProgress>().toEqualTypeOf<{
      currentIndex: number;
      totalTests: number;
      currentTest: string;
      elapsedMs: number;
      percentage: number;
    }>();
  });
});
