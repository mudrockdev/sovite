<script lang="ts">
	import { resolve } from '$app/paths';
	import { api } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import { bytes, dateTime, duration } from '#lib/format.ts';
	import { queueLabel } from '#lib/labels.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { queueNames, type Status } from '#lib/types.ts';

	let status = $state<Status | null>(null);
	let error = $state<unknown>(null);

	async function load() {
		try {
			status = await api.status();
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
		const timer = setInterval(() => {
			if (document.visibilityState === 'visible') load();
		}, 5000);
		return () => clearInterval(timer);
	});
</script>

<div class="mb-6 flex items-baseline justify-between">
	<h1 class="text-2xl font-semibold">{m.overview_title()}</h1>
	<span class="text-xs text-base-content/60">{m.auto_refresh()}</span>
</div>

{#if error}
	<div class="mb-4"><ErrorBanner {error} /></div>
{/if}

{#if status}
	{#if status.draining}
		<div role="status" class="mb-4 alert alert-soft alert-warning">
			<span>{m.draining()}</span>
		</div>
	{/if}

	<section aria-label={m.queue()} class="mb-6">
		<div class="stats w-full stats-vertical bg-base-100 shadow-sm sm:stats-horizontal">
			{#each queueNames as queue (queue)}
				<a href={resolve(`/queue?queue=${queue}`)} class="stat hover:bg-base-200">
					<div class="stat-title">{queueLabel[queue]()}</div>
					<div
						class={[
							'stat-value tabular-nums',
							queue === 'corrupt' && status.queue.corrupt > 0 && 'text-error'
						]}
					>
						{status.queue[queue]}
					</div>
				</a>
			{/each}
		</div>
	</section>

	<div class="grid gap-6 lg:grid-cols-2">
		<section class="card bg-base-100 shadow-sm">
			<div class="card-body">
				<h2 class="card-title">{m.server_info()}</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
					<dt class="text-base-content/60">{m.hostname()}</dt>
					<dd>{status.hostname}</dd>
					<dt class="text-base-content/60">{m.version()}</dt>
					<dd>{status.version}</dd>
					<dt class="text-base-content/60">{m.uptime()}</dt>
					<dd>{duration(status.uptime)}</dd>
					<dt class="text-base-content/60">{m.started()}</dt>
					<dd>{dateTime(status.started_at)}</dd>
					<dt class="text-base-content/60">{m.config_file()}</dt>
					<dd class="font-mono break-all">{status.config_path ?? m.none()}</dd>
					<dt class="text-base-content/60">{m.last_reload()}</dt>
					<dd>
						{#if !status.last_reload}
							{m.never()}
						{:else if status.last_reload.result === 'ok'}
							{m.reload_ok({ time: dateTime(status.last_reload.at) })}
						{:else}
							<span class="text-error">
								{m.reload_failed({
									time: dateTime(status.last_reload.at),
									error: status.last_reload.result
								})}
							</span>
						{/if}
					</dd>
				</dl>
			</div>
		</section>

		<section class="card bg-base-100 shadow-sm">
			<div class="card-body">
				<h2 class="card-title">{m.deliveries()}</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
					<dt class="text-base-content/60">{m.deliveries_running()}</dt>
					<dd class="tabular-nums">{status.deliveries.running}</dd>
					<dt class="text-base-content/60">{m.deliveries_ready()}</dt>
					<dd class="tabular-nums">{status.deliveries.ready}</dd>
				</dl>

				<h2 class="mt-4 card-title">{m.runtime()}</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
					<dt class="text-base-content/60">{m.memory()}</dt>
					<dd class="tabular-nums">{bytes(status.vm.memory)}</dd>
					<dt class="text-base-content/60">{m.processes()}</dt>
					<dd class="tabular-nums">{status.vm.processes}</dd>
					<dt class="text-base-content/60">{m.otp()}</dt>
					<dd>{status.vm.otp_release}</dd>
				</dl>
			</div>
		</section>

		<section class="card bg-base-100 shadow-sm lg:col-span-2">
			<div class="card-body">
				<h2 class="card-title">{m.listeners()}</h2>
				{#if status.listeners.length === 0}
					<p class="text-sm text-base-content/60">{m.no_listeners()}</p>
				{:else}
					<table class="table table-sm">
						<thead>
							<tr>
								<th>{m.listener()}</th>
								<th class="text-right">{m.connections()}</th>
							</tr>
						</thead>
						<tbody>
							{#each status.listeners as listener (listener.id)}
								<tr>
									<td class="font-mono">{listener.id}</td>
									<td class="text-right tabular-nums">{listener.connections}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		</section>
	</div>
{:else if !error}
	<span class="loading loading-spinner" aria-label={m.loading()}></span>
{/if}
