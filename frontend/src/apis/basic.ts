import axios from "axios";

export const BASE = import.meta.env.DEV ? "/api" : "";

axios.defaults.withCredentials = true;

const MUTATING_METHODS = new Set(["post", "put", "patch", "delete"]);

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

axios.interceptors.request.use((config) => {
  const method = (config.method ?? "get").toLowerCase();
  if (MUTATING_METHODS.has(method)) {
    const csrfToken = readCookie("admin_csrf");
    if (csrfToken) {
      config.headers.set("X-CSRF-Token", csrfToken);
    }
  }
  return config;
});

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

axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      window.dispatchEvent(new CustomEvent("myoauth:unauthorized"));
      for (const handler of unauthorizedHandlers) {
        handler();
      }
    }
    return Promise.reject(error);
  },
);

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
  if (axios.isAxiosError(err)) {
    const status = err.response?.status;
    const body = err.response?.data as ErrorBody | undefined;
    const message =
      body?.msg ||
      body?.error_description ||
      (status
        ? `${status} ${err.response?.statusText ?? ""}`.trim()
        : err.message);
    return new ApiError(message, status);
  }
  if (err instanceof Error) {
    return new ApiError(err.message);
  }
  return new ApiError(String(err));
}

async function unwrap<T extends CommonResp>(request: Promise<{ data: T }>) {
  try {
    const resp = await request;
    if (!resp.data.ok) {
      throw new ApiError(resp.data.msg || "request failed");
    }
    return resp.data;
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw toApiError(err);
  }
}

export function apiGet<T extends CommonResp>(url: string): Promise<T> {
  return unwrap<T>(axios.get(`${BASE}${url}`));
}

export function apiPost<TBody, TRes extends CommonResp>(
  url: string,
  body: TBody,
): Promise<TRes> {
  return unwrap<TRes>(axios.post(`${BASE}${url}`, body));
}

export function apiDelete<TBody, TRes extends CommonResp>(
  url: string,
  body: TBody,
): Promise<TRes> {
  return unwrap<TRes>(axios.delete(`${BASE}${url}`, { data: body }));
}
