<script lang="ts">
	import { ApiError, api } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import { m } from '#lib/paraglide/messages.js';
	import type { Setting } from '#lib/types.ts';

	type ReloadResult = { ok: boolean; message: string; errors: string[] };

	let settings = $state<Setting[] | null>(null);
	let error = $state<unknown>(null);
	let filter = $state('');
	let onlySet = $state(false);
	let reloading = $state(false);
	let reload = $state<ReloadResult | null>(null);

	const shown = $derived.by(() => {
		const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
		return (settings ?? []).filter(
			([key, value, isDefault]) =>
				!(onlySet && isDefault) &&
				words.every(
					(word) => key.toLowerCase().includes(word) || value.toLowerCase().includes(word)
				)
		);
	});

	async function load() {
		try {
			settings = await api.config();
			error = null;
		} catch (e) {
			error = e;
		}
	}

	$effect(() => {
		load();
	});

	async function reloadConfig() {
		reloading = true;
		try {
			await api.reload();
			reload = { ok: true, message: m.reloaded(), errors: [] };
			await load();
		} catch (e) {
			reload = reloadFailure(e);
		} finally {
			reloading = false;
		}
	}

	function reloadFailure(e: unknown): ReloadResult {
		if (e instanceof ApiError && Array.isArray(e.details.errors)) {
			return { ok: false, message: m.reload_invalid(), errors: e.details.errors.map(String) };
		}

		if (e instanceof ApiError && Array.isArray(e.details.keys)) {
			return {
				ok: false,
				message: m.reload_restart({ keys: e.details.keys.join(', ') }),
				errors: []
			};
		}

		return { ok: false, message: e instanceof Error ? e.message : String(e), errors: [] };
	}
</script>

<div class="mb-2 flex flex-wrap items-center justify-between gap-3">
	<h1 class="text-2xl font-semibold">{m.config_title()}</h1>
	<button type="button" onclick={reloadConfig} disabled={reloading} class="btn btn-primary btn-sm">
		{#if reloading}
			<span class="loading loading-xs loading-spinner"></span>
			{m.reloading()}
		{:else}
			{m.reload()}
		{/if}
	</button>
</div>
<p class="mb-6 text-sm text-base-content/70">{m.config_intro()}</p>

{#if reload}
	<div
		role={reload.ok ? 'status' : 'alert'}
		class={['mb-4 alert alert-soft', reload.ok ? 'alert-success' : 'alert-error']}
	>
		<div>
			<p>{reload.message}</p>
			{#if reload.errors.length > 0}
				<ul class="mt-2 list-disc pl-5 font-mono text-xs">
					{#each reload.errors as line, index (index)}
						<li>{line}</li>
					{/each}
				</ul>
			{/if}
		</div>
	</div>
{/if}

{#if error}
	<div class="mb-4"><ErrorBanner {error} /></div>
{/if}

{#if settings}
	<div class="mb-3 flex flex-wrap items-center gap-4">
		<label class="input w-full max-w-sm">
			<input
				type="search"
				bind:value={filter}
				placeholder={m.config_filter()}
				aria-label={m.config_filter()}
			/>
		</label>
		<label class="label text-sm">
			<input type="checkbox" bind:checked={onlySet} class="checkbox checkbox-sm" />
			{m.config_only_set()}
		</label>
		<span class="text-sm text-base-content/60">
			{m.config_count({ shown: shown.length, total: settings.length })}
		</span>
	</div>

	<div class="overflow-x-auto rounded-box bg-base-100 shadow-sm">
		<table class="table table-zebra table-sm">
			<thead>
				<tr>
					<th>{m.key()}</th>
					<th>{m.value()}</th>
				</tr>
			</thead>
			<tbody>
				{#each shown as [key, value, isDefault] (key)}
					<tr class="align-top">
						<td class="font-mono whitespace-nowrap">{key}</td>
						<td class="font-mono break-all">
							{value}
							{#if isDefault}<span class="ml-2 badge badge-ghost badge-xs">{m.default_value()}</span
								>{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{:else if !error}
	<span class="loading loading-spinner" aria-label={m.loading()}></span>
{/if}
