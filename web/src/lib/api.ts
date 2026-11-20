import { goto } from '$app/navigation';
import { session } from './session.svelte';

export class ApiError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

export interface ApiOptions {
	/** Redirect to /login when the server answers 401 (default true). */
	redirectOn401?: boolean;
	signal?: AbortSignal;
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function withQuery(path: string, query?: Query): string {
	if (!query) return path;
	const qs = new URLSearchParams();
	for (const [k, v] of Object.entries(query)) {
		if (v === undefined || v === null || v === '' || v === false) continue;
		qs.set(k, String(v));
	}
	const s = qs.toString();
	return s ? `${path}?${s}` : path;
}

export async function api<T = unknown>(
	method: string,
	path: string,
	body?: unknown,
	opts: ApiOptions = {}
): Promise<T> {
	const headers: Record<string, string> = { Accept: 'application/json' };
	let payload: BodyInit | undefined;
	if (body instanceof FormData) {
		payload = body;
	} else if (body !== undefined) {
		headers['Content-Type'] = 'application/json';
		payload = JSON.stringify(body);
	}

	let res: Response;
	try {
		res = await fetch(path, {
			method,
			headers,
			body: payload,
			credentials: 'same-origin',
			signal: opts.signal
		});
	} catch (e) {
		if (e instanceof DOMException && e.name === 'AbortError') throw e;
		throw new ApiError(0, 'Network error – is the server reachable?');
	}

	if (res.status === 401 && opts.redirectOn401 !== false) {
		session.me = null;
		await goto('/login');
		throw new ApiError(401, 'Please sign in.');
	}

	if (res.status === 204) return undefined as T;

	const text = await res.text();
	let data: unknown = undefined;
	if (text) {
		try {
			data = JSON.parse(text);
		} catch {
			data = text;
		}
	}

	if (!res.ok) {
		let msg = `Request failed (${res.status})`;
		if (data && typeof data === 'object' && 'error' in data) {
			msg = String((data as { error: unknown }).error);
		} else if (typeof data === 'string' && data.trim()) {
			msg = data.trim();
		}
		throw new ApiError(res.status, msg);
	}
	return data as T;
}

export const get = <T>(path: string, query?: Query, opts?: ApiOptions) =>
	api<T>('GET', withQuery(path, query), undefined, opts);
export const post = <T>(path: string, body?: unknown, opts?: ApiOptions) =>
	api<T>('POST', path, body, opts);
export const put = <T>(path: string, body?: unknown, opts?: ApiOptions) =>
	api<T>('PUT', path, body, opts);
export const patch = <T>(path: string, body?: unknown, opts?: ApiOptions) =>
	api<T>('PATCH', path, body, opts);
export const del = <T>(path: string, opts?: ApiOptions) => api<T>('DELETE', path, undefined, opts);

export function errMsg(e: unknown): string {
	if (e instanceof Error) return e.message;
	return String(e);
}
