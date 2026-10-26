// Localized names of API values.

import { m } from '#lib/paraglide/messages.js';
import type { MessageAction, Part, QueueName, RecipientStatus } from './types.ts';

export const queueLabel: Record<QueueName, () => string> = {
	incoming: m.queue_incoming,
	active: m.queue_active,
	deferred: m.queue_deferred,
	hold: m.queue_hold,
	corrupt: m.queue_corrupt
};

export const partLabel: Record<Part, () => string> = {
	mta: m.part_mta,
	filter: m.part_filter,
	mailbox: m.part_mailbox
};

export const statusLabel: Record<RecipientStatus['status'], () => string> = {
	pending: m.status_pending,
	deferred: m.status_deferred,
	delivered: m.status_delivered,
	failed: m.status_failed
};

export const actionLabel: Record<MessageAction, () => string> = {
	retry: m.action_retry,
	hold: m.action_hold,
	release: m.action_release,
	requeue: m.action_requeue,
	delete: m.action_delete
};

/** What can be done to a message in each queue (see Sovite.Core.MTA.QueueManager). */
export const queueActions: Record<QueueName, MessageAction[]> = {
	incoming: ['retry', 'hold', 'delete'],
	active: ['hold', 'requeue', 'delete'],
	deferred: ['retry', 'hold', 'requeue', 'delete'],
	hold: ['release', 'requeue', 'delete'],
	corrupt: ['requeue', 'delete']
};
