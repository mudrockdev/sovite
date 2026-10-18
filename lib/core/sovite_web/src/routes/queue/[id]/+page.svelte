<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { ApiError, api } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import MessageActions from '#lib/components/MessageActions.svelte';
	import QueueBadge from '#lib/components/QueueBadge.svelte';
	import { bytes, dateTime } from '#lib/format.ts';
	import { statusLabel } from '#lib/labels.ts';
	import { m } from '#lib/paraglide/messages.js';
	import type { MessageAction, MessageDetails, RecipientStatus } from '#lib/types.ts';

	const id = $derived(page.params.id ?? '');

	let message = $state<MessageDetails | null>(null);
	let missing = $state(false);
	let error = $state<unknown>(null);
	let notice = $state<string | null>(null);

	async function load(queueId: string) {
		try {
			message = await api.message(queueId);
			missing = false;
			error = null;
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) missing = true;
			else error = e;
			message = null;
		}
	}

	$effect(() => {
		load(id);
	});

	async function done(action: MessageAction) {
		if (action === 'delete') {
			await goto(resolve('/queue'));
			return;
		}

		notice = m.action_done({ id });
		await load(id);
	}

	const statusColor: Record<RecipientStatus['status'], string> = {
		pending: 'badge-ghost',
		deferred: 'badge-warning',
		delivered: 'badge-success',
		failed: 'badge-error'
	};

	const fields = $derived(
		message
			? [
					[m.arrival(), dateTime(message.received_at)],
					[m.size(), bytes(message.size)],
					[m.sender(), message.sender || m.null_sender()],
					[m.message_id(), message.message_id],
					[m.subject(), message.subject],
					[m.client(), message.client],
					[m.helo(), message.helo],
					[m.protocol(), message.protocol],
					[m.user(), message.user],
					[m.session(), message.session_id],
					[m.body_type(), message.body_type],
					[m.priority(), message.priority !== 0 ? String(message.priority) : null],
					['REQUIRETLS', message.requiretls ? m.yes() : null],
					['SMTPUTF8', message.smtputf8 ? m.yes() : null],
					['ENVID', message.envid],
					['RET', message.ret],
					[m.deliver_by(), dateTime(message.deliver_by)],
					[m.release_at(), dateTime(message.release_at)],
					[m.content_filter(), message.content_filter],
					[m.attempts(), message.attempts ? String(message.attempts) : null],
					[m.next_attempt(), dateTime(message.next_attempt)]
				].filter(([, value]) => value)
			: []
	);
</script>

<div class="breadcrumbs mb-2 text-sm">
	<ul>
		<li><a href={resolve('/queue')}>{m.nav_queue()}</a></li>
		<li class="font-mono">{id}</li>
	</ul>
</div>

<h1 class="mb-4 flex flex-wrap items-center gap-3 text-2xl font-semibold">
	<span class="font-mono">{m.message_title({ id })}</span>
	{#if message}<QueueBadge queue={message.queue} />{/if}
</h1>

{#if notice}
	<div role="status" class="mb-4 alert alert-soft alert-success"><span>{notice}</span></div>
{/if}
{#if error}
	<div class="mb-4"><ErrorBanner {error} /></div>
{/if}

{#if missing}
	<div class="card border border-dashed border-base-300 bg-base-100">
		<div class="card-body items-center text-base-content/60">
			<p>{m.not_found()}</p>
			<a href={resolve('/queue')} class="btn btn-ghost btn-sm">{m.back_to_queue()}</a>
		</div>
	</div>
{:else if message}
	<div class="mb-6">
		<MessageActions
			id={message.queue_id}
			queue={message.queue}
			ondone={done}
			onerror={(e) => (error = e)}
		/>
	</div>

	<section class="card mb-6 bg-base-100 shadow-sm">
		<div class="card-body">
			<h2 class="card-title">{m.envelope()}</h2>
			<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
				{#each fields as [name, value] (name)}
					<dt class="text-base-content/60">{name}</dt>
					<dd class="break-all">{value}</dd>
				{/each}
			</dl>
		</div>
	</section>

	<section class="card mb-6 bg-base-100 shadow-sm">
		<div class="card-body">
			<h2 class="card-title">{m.recipients()}</h2>
			<div class="overflow-x-auto">
				<table class="table table-sm">
					<thead>
						<tr>
							<th>{m.recipient()}</th>
							<th>{m.status()}</th>
							<th>{m.reply()}</th>
							<th>{m.notified()}</th>
						</tr>
					</thead>
					<tbody>
						{#each message.recipient_status as recipient (recipient.address)}
							<tr class="align-top">
								<td class="break-all">{recipient.address}</td>
								<td class="whitespace-nowrap">
									<span class="badge badge-soft badge-sm {statusColor[recipient.status]}">
										{statusLabel[recipient.status]()}
									</span>
									{#if recipient.code}<span class="ml-1 font-mono text-xs text-base-content/60"
											>{recipient.code}</span
										>{/if}
								</td>
								<td>
									{#if recipient.reply}
										<div class="break-all">{recipient.reply}</div>
										<div class="text-xs text-base-content/60">
											{[recipient.remote, dateTime(recipient.at)].filter(Boolean).join(' · ')}
										</div>
									{/if}
								</td>
								<td>{recipient.notified ? m.yes() : ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	</section>

	<section class="card bg-base-100 shadow-sm">
		<div class="card-body">
			<h2 class="card-title">{m.headers()}</h2>
			<pre
				class="overflow-x-auto rounded-box bg-base-200 p-4 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">{message.headers}</pre>
		</div>
	</section>
{:else if !error}
	<span class="loading loading-spinner" aria-label={m.loading()}></span>
{/if}
