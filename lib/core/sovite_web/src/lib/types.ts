// The admin API's responses (see Sovite.Core.Web.API).

export const queueNames = ['incoming', 'active', 'deferred', 'hold', 'corrupt'] as const;
export type QueueName = (typeof queueNames)[number];

export type Status = {
	version: string;
	hostname: string;
	started_at: string;
	uptime: number;
	config_path: string | null;
	last_reload: { at: string; result: string } | null;
	draining: boolean;
	listeners: { id: string; connections: number }[];
	queue: Record<QueueName, number>;
	deliveries: { running: number; ready: number };
	vm: { memory: number; processes: number; otp_release: string };
};

export type QueueMessage = {
	queue_id: string;
	queue: QueueName;
	size: number;
	received_at: string | null;
	sender: string;
	recipients: number;
	pending: string[];
	attempts: number;
	next_attempt: string | null;
	reason: string | null;
	priority: number;
	release_at: string | null;
};

/** A queue file that could not be read. */
export type UnreadableMessage = { queue_id: string; queue: QueueName; error: string };

export type RecipientStatus = {
	address: string;
	status: 'pending' | 'deferred' | 'delivered' | 'failed';
	code: string | null;
	reply: string | null;
	remote: string | null;
	at: string | null;
	notified: boolean;
};

export type MessageDetails = QueueMessage & {
	session_id: string | null;
	client: string | null;
	helo: string | null;
	protocol: string | null;
	user: string | null;
	body_type: string | null;
	requiretls: boolean;
	smtputf8: boolean;
	content_filter: string | null;
	envid: string | null;
	ret: string | null;
	deliver_by: string | null;
	recipient_status: RecipientStatus[];
	headers: string;
	message_id: string | null;
	subject: string | null;
};

export type MessageAction = 'retry' | 'hold' | 'release' | 'requeue' | 'delete';

export type RouteRecipient = {
	address: string;
	result: 'deliver' | 'defer' | 'fail' | 'discard';
	transport?: string;
	nexthop?: string;
	source?: Record<string, string>;
	login?: string | null;
	status?: string;
	text?: string;
};

export type RouteInfo = {
	address: string;
	rewritten?: string | null;
	domain?: string;
	class?: string;
	expanded?: string[] | null;
	error?: string;
	recipients: RouteRecipient[];
};

export type Trace = { queue_ids: string[]; lines: string[]; queued: MessageDetails[] };

/** A setting: key, value as TOML, and whether the value is the default. */
export type Setting = [key: string, value: string, isDefault: boolean];

export type ClusterMember = {
	node: string;
	status: 'self' | 'up' | 'down';
	since: string | null;
	hostname?: string;
	version?: string;
	uptime?: number;
	queue?: Record<QueueName, number>;
};

export type ClusterStatus =
	| { enabled: false }
	| {
			enabled: true;
			node: string;
			members: ClusterMember[];
			shared_config: { version: number; origin: string } | null;
			queue: { copies: Record<string, number>; taken_over: Record<string, number> };
	  };

export type IPPool = {
	name: string;
	overflow: string | null;
	addresses: {
		address: string;
		node: string | null;
		helo: string | null;
		sent_today: number;
		limit_today: number | null;
	}[];
};
