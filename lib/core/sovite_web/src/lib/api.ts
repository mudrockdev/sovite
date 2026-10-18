// A client of the admin API, on the same origin as the UI.

import { session } from './session.svelte.ts';
import type {
	MessageAction,
	MessageDetails,
	QueueMessage,
	QueueName,
	RouteInfo,
	Setting,
	Status,
	Trace,
	UnreadableMessage
} from './types.ts';

/** An error response: its status, message, and other fields (`errors`, `keys`). */
export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string,
		readonly details: Record<string, unknown> = {}
	) {
		super(message);
	}
}

async function request<T>(method: 'GET' | 'POST', path: string, token = session.token): Promise<T> {
	const response = await fetch(`/api${path}`, {
		method,
		headers: token ? { authorization: `Bearer ${token}` } : {},
		credentials: 'omit',
		cache: 'no-store'
	});

	const body = await response.json().catch(() => ({}));

	if (!response.ok) {
		// The token was revoked or replaced: sign in again.
		if (response.status === 401 && token === session.token) session.signOut();
		throw new ApiError(response.status, body.error ?? response.statusText, body);
	}

	return body as T;
}

const id = (value: string) => encodeURIComponent(value);

export const api = {
	/** Checks a token before it is kept. */
	check: (token: string) => request<Status>('GET', '/status', token),
	status: () => request<Status>('GET', '/status'),
	queue: (queue?: QueueName) =>
		request<{ messages: (QueueMessage | UnreadableMessage)[] }>(
			'GET',
			queue ? `/queue?queue=${queue}` : '/queue'
		).then((body) => body.messages),
	message: (queueId: string) => request<MessageDetails>('GET', `/queue/${id(queueId)}`),
	act: (queueId: string, action: MessageAction) =>
		request<{ ok: true }>('POST', `/queue/${id(queueId)}/${action}`),
	flush: () => request<{ ok: true }>('POST', '/queue/flush'),
	config: () => request<{ settings: Setting[] }>('GET', '/config').then((body) => body.settings),
	reload: () => request<{ ok: true }>('POST', '/config/reload'),
	route: (address: string, sender: string) =>
		request<RouteInfo>(
			'GET',
			`/route?${new URLSearchParams(sender ? { address, sender } : { address })}`
		),
	trace: (traceId: string) =>
		request<Trace>('GET', `/trace?${new URLSearchParams({ id: traceId })}`)
};

export function isUnreadable(
	message: QueueMessage | UnreadableMessage
): message is UnreadableMessage {
	return 'error' in message;
}
