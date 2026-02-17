import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api-client";

describe("api client", () => {
  it("uses the env base URL when not provided", async () => {
    const previous = process.env.NEXT_PUBLIC_API_BASE_URL;
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://example.test";

    const fetcher = vi.fn(async () => {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const client = createApiClient({ fetcher });
    await client.get<{ ok: boolean }>("/api/health");

    expect(fetcher).toHaveBeenCalledWith("http://example.test/api/health", expect.any(Object));

    if (previous) {
      process.env.NEXT_PUBLIC_API_BASE_URL = previous;
    } else {
      delete process.env.NEXT_PUBLIC_API_BASE_URL;
    }
  });

  it("sends JSON requests with defaults", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("accept")).toBe("application/json");
      expect(headers.get("content-type")).toBe("application/json");
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe(JSON.stringify({ hello: "world" }));
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const client = createApiClient({ fetcher, baseUrl: "http://example.test" });
    const response = await client.post<{ ok: boolean }, { hello: string }>("/api/tests", {
      hello: "world",
    });

    expect(response.ok).toBe(true);
  });

  it("throws ApiError with parsed payload", async () => {
    const fetcher = vi.fn(async () => {
      return new Response(JSON.stringify({ error: "Too many requests", retryAfter: 5 }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    });

    const client = createApiClient({ fetcher, baseUrl: "http://example.test" });

    try {
      await client.get("/api/tests");
      throw new Error("Expected ApiError");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      const apiError = error as ApiError;
      expect(apiError.status).toBe(429);
      expect(apiError.message).toBe("Too many requests");
      expect(apiError.payload?.retryAfter).toBe(5);
    }
  });

  it("parses SSE streams into events", async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("event: progress\n"));
        controller.enqueue(encoder.encode('data: {"step": 1}\n\n'));
        controller.enqueue(encoder.encode("event: result\n"));
        controller.enqueue(encoder.encode('data: {"done": true}\n\n'));
        controller.close();
      },
    });

    const fetcher = vi.fn(async () => {
      return new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    });

    const client = createApiClient({ fetcher, baseUrl: "http://example.test" });
    const events: Array<{ event: string; data: unknown }> = [];

    await client.stream("/api/analyse", {
      body: { headers: "X-Test" },
      onEvent: (event) => events.push({ event: event.event, data: event.data }),
    });

    expect(events).toEqual([
      { event: "progress", data: { step: 1 } },
      { event: "result", data: { done: true } },
    ]);
  });
});
