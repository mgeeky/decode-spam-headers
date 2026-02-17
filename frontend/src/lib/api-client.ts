const DEFAULT_BASE_URL = "http://localhost:8000";

export interface ApiErrorPayload {
  error?: string;
  detail?: string;
  retryAfter?: number;
  captchaChallenge?: {
    challengeToken: string;
    imageBase64: string;
  };
}

export class ApiError extends Error {
  status: number;
  payload?: ApiErrorPayload;
  rawBody?: string;

  constructor(message: string, status: number, payload?: ApiErrorPayload, rawBody?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
    this.rawBody = rawBody;
  }
}

export interface SseEvent<T = unknown> {
  event: string;
  data: T;
  raw: string;
}

export interface StreamRequestOptions<TBody, TEvent> {
  body: TBody;
  headers?: HeadersInit;
  signal?: AbortSignal;
  onEvent: (event: SseEvent<TEvent>) => void;
  method?: "POST" | "PUT";
}

export interface ApiClient {
  request<TResponse>(path: string, init?: RequestInit & { body?: unknown }): Promise<TResponse>;
  get<TResponse>(path: string, init?: RequestInit): Promise<TResponse>;
  post<TResponse, TBody>(path: string, body: TBody, init?: RequestInit): Promise<TResponse>;
  stream<TBody, TEvent>(path: string, options: StreamRequestOptions<TBody, TEvent>): Promise<void>;
}

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface ApiClientOptions {
  baseUrl?: string;
  fetcher?: Fetcher;
  defaultHeaders?: HeadersInit;
}

const JSON_ACCEPT_HEADER: HeadersInit = { Accept: "application/json" };
const JSON_CONTENT_HEADER: HeadersInit = { "Content-Type": "application/json" };
const SSE_ACCEPT_HEADER: HeadersInit = { Accept: "text/event-stream" };

const mergeHeaders = (base?: HeadersInit, overrides?: HeadersInit): Headers => {
  const merged = new Headers(base);
  if (overrides) {
    const next = new Headers(overrides);
    next.forEach((value, key) => merged.set(key, value));
  }
  return merged;
};

const resolveUrl = (baseUrl: string, path: string): string => {
  return new URL(path, baseUrl).toString();
};

const isBodyInit = (body: unknown): body is BodyInit | null => {
  if (body === null) {
    return true;
  }
  if (typeof body === "string") {
    return true;
  }
  if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) {
    return true;
  }
  if (typeof Blob !== "undefined" && body instanceof Blob) {
    return true;
  }
  if (typeof FormData !== "undefined" && body instanceof FormData) {
    return true;
  }
  if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
    return true;
  }
  if (typeof ArrayBuffer !== "undefined" && body instanceof ArrayBuffer) {
    return true;
  }
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) {
    return true;
  }
  return false;
};

const parseErrorResponse = async (
  response: Response,
): Promise<{ message: string; payload?: ApiErrorPayload; rawBody?: string }> => {
  const fallbackMessage = `Request failed with status ${response.status}`;
  let payload: ApiErrorPayload | undefined;
  let rawBody: string | undefined;

  try {
    const json = (await response.clone().json()) as ApiErrorPayload;
    if (json && typeof json === "object") {
      payload = json;
      const message = json.error ?? json.detail;
      return { message: message ?? fallbackMessage, payload };
    }
  } catch {
    // Ignore JSON parsing errors and fall back to text.
  }

  try {
    rawBody = await response.text();
  } catch {
    rawBody = undefined;
  }

  return {
    message: rawBody && rawBody.trim().length > 0 ? rawBody : fallbackMessage,
    payload,
    rawBody,
  };
};

const parseResponse = async <TResponse>(response: Response): Promise<TResponse> => {
  if (response.status === 204) {
    return undefined as TResponse;
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as TResponse;
  }
  return (await response.text()) as unknown as TResponse;
};

const parseSseData = <T>(raw: string): T => {
  if (raw.trim().length === 0) {
    return "" as T;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    return raw as unknown as T;
  }
};

const parseSseBlock = <T>(block: string): SseEvent<T> | null => {
  const lines = block.split("\n");
  let event = "message";
  const dataLines: string[] = [];
  for (const line of lines) {
    if (!line || line.startsWith(":")) {
      continue;
    }
    if (line.startsWith("event:")) {
      event = line.slice("event:".length).trim() || "message";
      continue;
    }
    if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).replace(/^\s/, ""));
    }
  }
  if (dataLines.length === 0) {
    return null;
  }
  const raw = dataLines.join("\n");
  return {
    event,
    data: parseSseData<T>(raw),
    raw,
  };
};

export const readSseStream = async <TEvent>(
  stream: ReadableStream<Uint8Array>,
  onEvent: (event: SseEvent<TEvent>) => void,
  signal?: AbortSignal,
): Promise<void> => {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      if (signal?.aborted) {
        await reader.cancel();
        throw new DOMException("The request was aborted", "AbortError");
      }

      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      const normalized = buffer.replace(/\r\n/g, "\n");
      const parts = normalized.split("\n\n");
      buffer = parts.pop() ?? "";
      for (const part of parts) {
        const event = parseSseBlock<TEvent>(part.trim());
        if (event) {
          onEvent(event);
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (buffer.trim().length > 0) {
    const event = parseSseBlock<TEvent>(buffer.replace(/\r\n/g, "\n").trim());
    if (event) {
      onEvent(event);
    }
  }
};

export const createApiClient = (options: ApiClientOptions = {}): ApiClient => {
  const baseUrl = options.baseUrl ?? process.env.NEXT_PUBLIC_API_BASE_URL ?? DEFAULT_BASE_URL;
  const fetcher = options.fetcher ?? fetch;
  const defaultHeaders = options.defaultHeaders;

  const request = async <TResponse>(
    path: string,
    init: RequestInit & { body?: unknown } = {},
  ): Promise<TResponse> => {
    const url = resolveUrl(baseUrl, path);
    const { body, headers, ...rest } = init;
    const hasJsonBody = body !== undefined && !isBodyInit(body);

    const baseHeaders = mergeHeaders(JSON_ACCEPT_HEADER, defaultHeaders);
    const withContent = hasJsonBody ? mergeHeaders(baseHeaders, JSON_CONTENT_HEADER) : baseHeaders;
    const finalHeaders = mergeHeaders(withContent, headers);

    const response = await fetcher(url, {
      ...rest,
      headers: finalHeaders,
      body:
        body === undefined
          ? undefined
          : hasJsonBody
            ? JSON.stringify(body)
            : (body as BodyInit | null),
    });

    if (!response.ok) {
      const { message, payload, rawBody } = await parseErrorResponse(response);
      throw new ApiError(message, response.status, payload, rawBody);
    }

    return parseResponse<TResponse>(response);
  };

  const get = async <TResponse>(path: string, init: RequestInit = {}): Promise<TResponse> => {
    return request<TResponse>(path, { ...init, method: "GET" });
  };

  const post = async <TResponse, TBody>(
    path: string,
    body: TBody,
    init: RequestInit = {},
  ): Promise<TResponse> => {
    return request<TResponse>(path, { ...init, method: "POST", body });
  };

  const stream = async <TBody, TEvent>(
    path: string,
    options: StreamRequestOptions<TBody, TEvent>,
  ): Promise<void> => {
    const { body, headers, signal, onEvent, method } = options;
    const url = resolveUrl(baseUrl, path);
    const baseHeaders = mergeHeaders(SSE_ACCEPT_HEADER, defaultHeaders);
    const withContent = mergeHeaders(baseHeaders, JSON_CONTENT_HEADER);
    const finalHeaders = mergeHeaders(withContent, headers);

    const response = await fetcher(url, {
      method: method ?? "POST",
      headers: finalHeaders,
      body: JSON.stringify(body),
      signal,
    });

    if (!response.ok) {
      const { message, payload, rawBody } = await parseErrorResponse(response);
      throw new ApiError(message, response.status, payload, rawBody);
    }

    if (!response.body) {
      throw new ApiError("Response body missing for SSE stream", response.status);
    }

    await readSseStream<TEvent>(response.body, onEvent, signal);
  };

  return {
    request,
    get,
    post,
    stream,
  };
};

export const apiClient = createApiClient();
