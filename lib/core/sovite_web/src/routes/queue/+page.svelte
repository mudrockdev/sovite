<script lang="ts">
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { api, isUnreadable } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import MessageActions from '#lib/components/MessageActions.svelte';
	import QueueBadge from '#lib/components/QueueBadge.svelte';
	import { bytes, dateTime } from '#lib/format.ts';
	import { queueLabel } from '#lib/labels.ts';
	import { m } from '#lib/paraglide/messages.js';
	import {
		queueNames,
		type QueueMessage,
		type QueueName,
		type UnreadableMessage
	} from '#lib/types.ts';

	const queue = $derived.by(() => {
		const name = page.url.searchParams.get('queue');
		return queueNames.find((q) => q === name);
	});

	let messages = $state<(QueueMessage | UnreadableMessage)[] | null>(null);
	let error = $state<unknown>(null);
	let notice = $state<string | null>(null);

	const total = $derived(
		(messages ?? []).reduce((sum, message) => sum + (isUnreadable(message) ? 0 : message.size), 0)
	);

	async function load(name: QueueName | undefined) {
		try {
			messages = await api.queue(name);
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load(queue);
	});

	async function flush() {
		try {
			await api.flush();
			notice = m.flushed();
			await load(queue);
		} catch (e) {
			error = e;
		}
	}

	function done(id: string) {
		notice = m.action_done({ id });
		load(queue);
	}
</script>

<div class="mb-4 flex flex-wrap items-center justify-between gap-3">
	<h1 class="text-2xl font-semibold">{m.queue_title()}</h1>
	<div class="flex gap-2">
		<button type="button" onclick={() => load(queue)} class="btn btn-outline btn-sm">
			{m.refresh()}
		</button>
		<button type="button" onclick={flush} class="btn btn-primary btn-sm">{m.flush()}</button>
	</div>
</div>

<nav aria-label={m.queue_filter()} class="tabs tabs-box mb-4 w-fit bg-base-100">
	<a
		href={resolve('/queue')}
		class={['tab', !queue && 'tab-active']}
		aria-current={!queue ? 'page' : undefined}
	>
		{m.queue_all()}
	</a>
	{#each queueNames as name (name)}
		<a
			href={resolve(`/queue?queue=${name}`)}
			class={['tab', queue === name && 'tab-active']}
			aria-current={queue === name ? 'page' : undefined}
		>
			{queueLabel[name]()}
		</a>
	{/each}
</nav>

{#if notice}
	<div role="status" class="mb-4 alert alert-soft alert-success"><span>{notice}</span></div>
{/if}
{#if error}
	<div class="mb-4"><ErrorBanner {error} /></div>
{/if}

{#if messages === null}
	{#if !error}<span class="loading loading-spinner" aria-label={m.loading()}></span>{/if}
{:else if messages.length === 0}
	<div class="card border border-dashed border-base-300 bg-base-100">
		<div class="card-body items-center text-base-content/60">{m.queue_empty()}</div>
	</div>
{:else}
	<p class="mb-2 text-sm text-base-content/60">
		{m.message_count({ count: messages.length, size: bytes(total) })}
	</p>
	<div class="overflow-x-auto rounded-box bg-base-100 shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr>
					<th>{m.queue_id()}</th>
					<th>{m.queue()}</th>
					<th>{m.arrival()}</th>
					<th>{m.sender()}</th>
					<th>{m.pending()}</th>
					<th class="text-right">{m.size()}</th>
					<th>{m.actions()}</th>
				</tr>
			</thead>
			<tbody>
				{#each messages as message (message.queue_id)}
					<tr class="align-top hover:bg-base-200">
						<td class="font-mono">
							<a href={resolve('/queue/[id]', { id: message.queue_id })} class="link link-primary">
								{message.queue_id}
							</a>
						</td>
						<td><QueueBadge queue={message.queue} /></td>
						{#if isUnreadable(message)}
							<td colspan="4" class="text-error">{m.unreadable({ error: message.error })}</td>
						{:else}
							<td class="whitespace-nowrap">{dateTime(message.received_at)}</td>
							<td class="break-all">{message.sender || m.null_sender()}</td>
							<td>
								<div class="break-all">{message.pending.join(', ')}</div>
								{#if message.reason}
									<div class="mt-1 text-xs text-warning">{message.reason}</div>
								{/if}
								{#if message.release_at}
									<div class="mt-1 text-xs text-base-content/60">
										{m.on_hold_until({ time: dateTime(message.release_at) })}
									</div>
								{/if}
							</td>
							<td class="text-right whitespace-nowrap tabular-nums">{bytes(message.size)}</td>
						{/if}
						<td>
							<MessageActions
								id={message.queue_id}
								queue={message.queue}
								ondone={() => done(message.queue_id)}
								onerror={(e) => (error = e)}
							/>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
