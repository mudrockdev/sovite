<script lang="ts">
	import { resolve } from '$app/paths';
	import { api } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import { queueLabel } from '#lib/labels.ts';
	import { m } from '#lib/paraglide/messages.js';
	import type { Trace } from '#lib/types.ts';

	let id = $state('');
	let trace = $state<Trace | null>(null);
	let error = $state<unknown>(null);
	let busy = $state(false);

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		try {
			trace = await api.trace(id.trim());
			error = null;
		} catch (e) {
			error = e;
			trace = null;
		} finally {
			busy = false;
		}
	}
</script>

<h1 class="mb-2 text-2xl font-semibold">{m.trace_title()}</h1>
<p class="mb-6 max-w-3xl text-sm text-base-content/70">{m.trace_intro()}</p>

<form onsubmit={submit} class="card mb-6 bg-base-100 shadow-sm">
	<div class="card-body flex-row flex-wrap items-end gap-4">
		<fieldset class="fieldset min-w-64 flex-1">
			<legend class="fieldset-legend">{m.trace_id()}</legend>
			<input
				type="text"
				bind:value={id}
				required
				spellcheck="false"
				placeholder="8CboABCDEFGHIJ"
				class="input w-full font-mono"
			/>
		</fieldset>
		<button type="submit" disabled={busy} class="btn btn-primary">{m.trace_submit()}</button>
	</div>
</form>

{#if error}
	<ErrorBanner {error} />
{/if}

{#if trace}
	{#if trace.lines.length === 0}
		<div class="card border border-dashed border-base-300 bg-base-100">
			<div class="card-body items-center text-base-content/60">{m.trace_none()}</div>
		</div>
	{:else}
		<div class="mb-4 flex flex-wrap items-center gap-2 text-sm">
			<span class="text-base-content/60">{m.trace_queue_ids()}:</span>
			{#each trace.queue_ids as queueId (queueId)}
				<a href={resolve('/queue/[id]', { id: queueId })} class="badge badge-outline font-mono"
					>{queueId}</a
				>
			{/each}
		</div>

		{#each trace.queued as message (message.queue_id)}
			<div role="status" class="mb-2 alert alert-soft alert-warning">
				<span
					>{m.trace_still_queued({
						id: message.queue_id,
						queue: queueLabel[message.queue]()
					})}</span
				>
			</div>
		{/each}

		<section class="card bg-base-100 shadow-sm">
			<div class="card-body">
				<h2 class="card-title">{m.trace_lines()}</h2>
				<ol class="space-y-1 rounded-box bg-base-200 p-4 font-mono text-xs leading-relaxed">
					{#each trace.lines as line, index (index)}
						<li class="break-all whitespace-pre-wrap">{line}</li>
					{/each}
				</ol>
			</div>
		</section>
	{/if}
{/if}
