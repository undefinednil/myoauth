export const BASE = import.meta.env.DEV ? "/api" : "";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function readCookie(name: string): string {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return "";
}

type UnauthorizedHandler = () => void;

const unauthorizedHandlers = new Set<UnauthorizedHandler>();

export function setUnauthorizedHandler(
  handler: UnauthorizedHandler,
): () => void {
  unauthorizedHandlers.add(handler);
  return () => {
    unauthorizedHandlers.delete(handler);
  };
}

function handleUnauthorized(): void {
  window.dispatchEvent(new CustomEvent("myoauth:unauthorized"));
  for (const handler of unauthorizedHandlers) {
    handler();
  }
}

export type CommonResp = {
  ok: boolean;
  msg: string;
};

export class ApiError extends Error {
  readonly status?: number;
  readonly unauthorized: boolean;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.unauthorized = status === 401;
  }
}

type ErrorBody = {
  msg?: string;
  error?: string;
  error_description?: string;
};

export function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

function toApiError(err: unknown): ApiError {
  if (err instanceof Error) {
    return new ApiError(err.message);
  }
  return new ApiError(String(err));
}

function http(method: string, url: string, body?: unknown): Promise<Response> {
  const headers = new Headers({ Accept: "application/json" });
  if (MUTATING_METHODS.has(method)) {
    const csrfToken = readCookie("admin_csrf");
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }
  let payload: string | undefined;
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
    payload = JSON.stringify(body);
  }
  return fetch(`${BASE}${url}`, {
    method,
    headers,
    body: payload,
    credentials: "include",
  });
}

async function parseBody(resp: Response): Promise<unknown> {
  const text = await resp.text().catch(() => "");
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function unwrap<T extends CommonResp>(
  request: Promise<Response>,
): Promise<T> {
  const resp = await request.catch((err) => {
    throw toApiError(err);
  });
  const data = await parseBody(resp);
  if (resp.status === 401) {
    handleUnauthorized();
  }
  if (!resp.ok) {
    const body = data as ErrorBody | undefined;
    const message =
      body?.msg ||
      body?.error_description ||
      `${resp.status} ${resp.statusText}`.trim();
    throw new ApiError(message, resp.status);
  }
  const common = data as CommonResp | undefined;
  if (!common?.ok) {
    throw new ApiError(common?.msg || "request failed");
  }
  return common as T;
}

export function apiGet<T extends CommonResp>(url: string): Promise<T> {
  return unwrap<T>(http("GET", url));
}

export function apiPost<TBody, TRes extends CommonResp>(
  url: string,
  body: TBody,
): Promise<TRes> {
  return unwrap<TRes>(http("POST", url, body));
}

export function apiDelete<TBody, TRes extends CommonResp>(
  url: string,
  body: TBody,
): Promise<TRes> {
  return unwrap<TRes>(http("DELETE", url, body));
}
