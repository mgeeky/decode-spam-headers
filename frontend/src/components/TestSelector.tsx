"use client";

import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faCheck,
  faChevronDown,
  faMagnifyingGlass,
  faXmark,
} from "@fortawesome/free-solid-svg-icons";

import { createApiClient } from "../lib/api-client";

type TestInfo = {
  id: number;
  name: string;
  category: string;
};

type TestsResponse = {
  tests: TestInfo[];
  totalCount: number;
};

type TestSelectorProps = {
  selectedTestIds: number[];
  onSelectionChange: (next: number[]) => void;
};

type TestGroup = {
  category: string;
  tests: TestInfo[];
};

const buildGroups = (tests: TestInfo[]): TestGroup[] => {
  const groups = new Map<string, TestInfo[]>();
  for (const test of tests) {
    const current = groups.get(test.category) ?? [];
    current.push(test);
    groups.set(test.category, current);
  }

  return Array.from(groups.entries()).map(([category, groupedTests]) => ({
    category,
    tests: groupedTests,
  }));
};

const handleActionKeyDown = (
  event: KeyboardEvent<HTMLButtonElement>,
  onAction: () => void,
): void => {
  if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
    event.preventDefault();
    onAction();
  }
};

export default function TestSelector({ selectedTestIds, onSelectionChange }: TestSelectorProps) {
  const [tests, setTests] = useState<TestInfo[]>([]);
  const [searchText, setSearchText] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const client = useMemo(
    () =>
      createApiClient({
        fetcher: (...args) => globalThis.fetch(...args),
      }),
    [],
  );

  useEffect(() => {
    let isActive = true;

    const loadTests = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const response = await client.get<TestsResponse>("/api/tests");
        if (!isActive) {
          return;
        }
        setTests(response.tests ?? []);
      } catch {
        if (!isActive) {
          return;
        }
        setError("Unable to load analysis tests.");
      } finally {
        if (isActive) {
          setIsLoading(false);
        }
      }
    };

    void loadTests();

    return () => {
      isActive = false;
    };
  }, [client]);

  const normalizedSearch = searchText.trim().toLowerCase();
  const filteredTests = useMemo(() => {
    if (!normalizedSearch) {
      return tests;
    }
    return tests.filter((test) => test.name.toLowerCase().includes(normalizedSearch));
  }, [normalizedSearch, tests]);

  const groupedTests = useMemo(() => buildGroups(filteredTests), [filteredTests]);
  const selectedSet = useMemo(() => new Set(selectedTestIds), [selectedTestIds]);

  const handleSelectAll = () => {
    onSelectionChange(tests.map((test) => test.id));
  };

  const handleDeselectAll = () => {
    onSelectionChange([]);
  };

  const handleToggleTest = (id: number) => {
    if (selectedSet.has(id)) {
      onSelectionChange(selectedTestIds.filter((testId) => testId !== id));
      return;
    }

    onSelectionChange([...selectedTestIds, id]);
  };

  const totalCount = tests.length;
  const visibleCount = filteredTests.length;

  return (
    <section
      className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.25)]"
      data-testid="test-selector"
    >
      <details open className="group">
        <summary className="flex cursor-pointer list-none items-center justify-between text-xs uppercase tracking-[0.2em] text-info/90">
          <span>Test Selection</span>
          <span className="flex items-center gap-2 font-mono text-[10px] text-text/50">
            {visibleCount} / {totalCount}
            <FontAwesomeIcon icon={faChevronDown} className="text-[10px] text-text/40" />
          </span>
        </summary>
        <div className="mt-4 flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex flex-1 items-center gap-2 rounded-full border border-info/20 bg-background/40 px-3 py-2 text-sm text-text/70 focus-within:border-info/40">
              <FontAwesomeIcon icon={faMagnifyingGlass} className="text-xs text-text/40" />
              <input
                type="text"
                value={searchText}
                onInput={(event) => setSearchText(event.currentTarget.value)}
                className="flex-1 bg-transparent text-xs text-text/80 outline-none"
                placeholder="Search tests"
                data-testid="test-search-input"
                aria-label="Search analysis tests"
              />
            </label>
            <button
              type="button"
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
              onClick={handleSelectAll}
              onKeyDown={(event) => handleActionKeyDown(event, handleSelectAll)}
              data-testid="select-all-tests"
            >
              <FontAwesomeIcon icon={faCheck} className="text-xs" />
              Select All
            </button>
            <button
              type="button"
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
              onClick={handleDeselectAll}
              onKeyDown={(event) => handleActionKeyDown(event, handleDeselectAll)}
              data-testid="deselect-all-tests"
            >
              <FontAwesomeIcon icon={faXmark} className="text-xs" />
              Deselect All
            </button>
          </div>

          {isLoading ? (
            <p className="text-xs text-text/60">Loading tests...</p>
          ) : null}
          {error ? (
            <p role="alert" className="text-xs text-spam">
              {error}
            </p>
          ) : null}

          <div className="grid gap-4">
            {groupedTests.map((group) => (
              <div
                key={group.category}
                className="rounded-xl border border-info/10 bg-background/40 p-4"
              >
                <div className="flex items-center justify-between text-xs uppercase tracking-[0.2em] text-info/80">
                  <span>{group.category}</span>
                  <span className="font-mono text-[10px] text-text/50">
                    {group.tests.length} tests
                  </span>
                </div>
                <div className="mt-3 flex flex-col gap-2">
                  {group.tests.map((test) => (
                    <label
                      key={test.id}
                      className="flex items-start gap-3 rounded-lg border border-info/10 bg-surface/40 p-3 text-sm text-text/80"
                    >
                      <input
                        type="checkbox"
                        className="mt-1 h-4 w-4 rounded border-info/40 text-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
                        checked={selectedSet.has(test.id)}
                        onChange={() => handleToggleTest(test.id)}
                        data-testid={`test-checkbox-${test.id}`}
                        aria-label={test.name}
                      />
                      <span className="flex flex-col gap-1">
                        <span className="font-medium">{test.name}</span>
                        <span className="font-mono text-[10px] text-text/50">ID {test.id}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            ))}
            {groupedTests.length === 0 && !isLoading ? (
              <p className="text-xs text-text/60">No tests match the current search.</p>
            ) : null}
          </div>
        </div>
      </details>
    </section>
  );
}
