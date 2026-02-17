export type HeaderInputSource = "paste" | "file";

export interface HeaderInput {
  rawText: string;
  source: HeaderInputSource;
  fileName?: string;
}

export interface AnalysisConfig {
  testIds: number[];
  resolve: boolean;
  decodeAll: boolean;
}

export type TestSeverity = "spam" | "suspicious" | "clean" | "info";

export type TestStatus = "success" | "error" | "skipped";

export interface TestResult {
  testId: number;
  testName: string;
  headerName: string;
  headerValue: string;
  analysis: string;
  description: string;
  severity: TestSeverity;
  status: TestStatus;
  error?: string | null;
}

export interface HopChainNode {
  index: number;
  hostname: string;
  ip?: string;
  timestamp?: string;
  serverInfo?: string;
  delay?: number | null;
}

export interface SecurityAppliance {
  name: string;
  vendor: string;
  headers: string[];
}

export interface ReportMetadata {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  skippedTests: number;
  elapsedMs: number;
  timedOut: boolean;
  incompleteTests: string[];
}

export interface AnalysisReport {
  results: TestResult[];
  hopChain: HopChainNode[];
  securityAppliances: SecurityAppliance[];
  metadata: ReportMetadata;
}

export interface AnalysisProgress {
  currentIndex: number;
  totalTests: number;
  currentTest: string;
  elapsedMs: number;
  percentage: number;
}
