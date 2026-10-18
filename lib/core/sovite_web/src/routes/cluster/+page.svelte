<script lang="ts">
	import { ApiError, api } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import { dateTime } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import type { ClusterMember, ClusterStatus, IPPool } from '#lib/types.ts';

	type Result = { ok: boolean; message: string; errors: string[] };

	let cluster = $state<ClusterStatus | null>(null);
	let pools = $state<IPPool[] | null>(null);
	let error = $state<unknown>(null);

	let content = $state('');
	let pushing = $state(false);
	let pushed = $state<Result | null>(null);

	let peer = $state('');
	let joining = $state(false);
	let joined = $state<Result | null>(null);

	async function load() {
		try {
			[cluster, pools] = await Promise.all([api.cluster(), api.ipPools()]);
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

	function failure(e: unknown, invalid: string): Result {
		if (e instanceof ApiError && Array.isArray(e.details.errors)) {
			return { ok: false, message: invalid, errors: e.details.errors.map(String) };
		}

		return { ok: false, message: e instanceof Error ? e.message : String(e), errors: [] };
	}

	async function push(event: SubmitEvent) {
		event.preventDefault();
		pushing = true;
		try {
			const { version } = await api.pushConfig(content);
			pushed = { ok: true, message: m.cluster_pushed({ version }), errors: [] };
			await load();
		} catch (e) {
			pushed = failure(e, m.cluster_push_invalid());
		} finally {
			pushing = false;
		}
	}

	async function join(event: SubmitEvent) {
		event.preventDefault();
		joining = true;
		try {
			await api.join(peer.trim());
			joined = { ok: true, message: m.cluster_joined({ peer: peer.trim() }), errors: [] };
			await load();
		} catch (e) {
			joined = failure(e, '');
		} finally {
			joining = false;
		}
	}

	const stateLabel: Record<ClusterMember['status'], () => string> = {
		self: m.cluster_state_self,
		up: m.cluster_state_up,
		down: m.cluster_state_down
	};

	const stateBadge: Record<ClusterMember['status'], string> = {
		self: 'badge-info',
		up: 'badge-success',
		down: 'badge-error'
	};

	function queued(member: ClusterMember): string {
		if (!member.queue) return '';
		return String(Object.values(member.queue).reduce((sum, count) => sum + count, 0));
	}
</script>

{#snippet outcome(result: Result)}
	<div role="status" class={['alert alert-soft', result.ok ? 'alert-success' : 'alert-error']}>
		<div>
			<p>{result.message}</p>
			{#if result.errors.length > 0}
				<ul class="mt-1 list-disc pl-5 font-mono text-xs">
					{#each result.errors as line, index (index)}
						<li>{line}</li>
					{/each}
				</ul>
			{/if}
		</div>
	</div>
{/snippet}

<div class="mb-2 flex items-baseline justify-between">
	<h1 class="text-2xl font-semibold">{m.cluster_title()}</h1>
	<span class="text-xs text-base-content/60">{m.auto_refresh()}</span>
</div>
<p class="mb-6 max-w-3xl text-sm text-base-content/70">{m.cluster_intro()}</p>

{#if error}
	<div class="mb-4"><ErrorBanner {error} /></div>
{/if}

{#if cluster && !cluster.enabled}
	<div role="status" class="mb-6 alert alert-soft alert-info">
		<span>{m.cluster_off()}</span>
	</div>
{:else if cluster && cluster.enabled}
	<div class="mb-6 grid gap-6 lg:grid-cols-2">
		<section class="card bg-base-100 shadow-sm lg:col-span-2">
			<div class="card-body">
				<h2 class="card-title">{m.cluster_members()}</h2>
				<p class="text-sm text-base-content/70">
					{m.cluster_this_node()}: <span class="font-mono">{cluster.node}</span>
				</p>
				<div class="overflow-x-auto">
					<table class="table table-sm">
						<thead>
							<tr>
								<th>{m.cluster_node()}</th>
								<th>{m.cluster_state()}</th>
								<th>{m.hostname()}</th>
								<th>{m.version()}</th>
								<th class="text-right">{m.cluster_queued()}</th>
								<th>{m.cluster_since()}</th>
							</tr>
						</thead>
						<tbody>
							{#each cluster.members as member (member.node)}
								<tr>
									<td class="font-mono">{member.node}</td>
									<td>
										<span class={['badge badge-soft badge-sm', stateBadge[member.status]]}>
											{stateLabel[member.status]()}
										</span>
									</td>
									<td>{member.hostname ?? ''}</td>
									<td>{member.version ?? ''}</td>
									<td class="text-right tabular-nums">{queued(member)}</td>
									<td>{member.since ? dateTime(member.since) : ''}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>

				{#if Object.keys(cluster.queue.copies).length > 0 || Object.values(cluster.queue.taken_over).some((count) => count > 0)}
					<h3 class="mt-2 font-semibold">{m.cluster_copies()}</h3>
					<ul class="text-sm">
						{#each Object.entries(cluster.queue.copies) as [node, count] (node)}
							<li>{m.cluster_copies_of({ node, count })}</li>
						{/each}
						{#each Object.entries(cluster.queue.taken_over) as [node, count] (node)}
							{#if count > 0}
								<li class="text-warning">{m.cluster_taken_over({ node, count })}</li>
							{/if}
						{/each}
					</ul>
				{/if}
			</div>
		</section>

		<section class="card bg-base-100 shadow-sm">
			<form class="card-body" onsubmit={push}>
				<h2 class="card-title">{m.cluster_shared()}</h2>
				<p class="text-sm">
					{#if cluster.shared_config}
						{m.cluster_shared_version(cluster.shared_config)}
					{:else}
						{m.cluster_shared_none()}
					{/if}
				</p>
				<fieldset class="fieldset">
					<legend class="fieldset-legend">{m.cluster_push()}</legend>
					<textarea
						bind:value={content}
						required
						spellcheck="false"
						rows="8"
						class="textarea w-full font-mono text-xs"></textarea>
					<p class="label whitespace-normal">{m.cluster_push_help()}</p>
				</fieldset>
				<div class="card-actions">
					<button type="submit" disabled={pushing} class="btn btn-primary">
						{pushing ? m.cluster_pushing() : m.cluster_push()}
					</button>
				</div>
				{#if pushed}
					{@render outcome(pushed)}
				{/if}
			</form>
		</section>

		<section class="card bg-base-100 shadow-sm">
			<form class="card-body" onsubmit={join}>
				<h2 class="card-title">{m.cluster_join()}</h2>
				<fieldset class="fieldset">
					<legend class="fieldset-legend">{m.cluster_node()}</legend>
					<input
						type="text"
						bind:value={peer}
						required
						spellcheck="false"
						placeholder="mx2@10.0.0.2:4370"
						class="input w-full font-mono"
					/>
					<p class="label whitespace-normal">{m.cluster_join_help()}</p>
				</fieldset>
				<div class="card-actions">
					<button type="submit" disabled={joining} class="btn">{m.cluster_join_submit()}</button>
				</div>
				{#if joined}
					{@render outcome(joined)}
				{/if}
			</form>
		</section>
	</div>
{:else if !error}
	<span class="loading loading-spinner" aria-label={m.loading()}></span>
{/if}

{#if pools}
	<section class="card bg-base-100 shadow-sm">
		<div class="card-body">
			<h2 class="card-title">{m.ip_pools()}</h2>
			{#if pools.length === 0}
				<p class="text-sm text-base-content/60">{m.ip_pools_none()}</p>
			{:else}
				{#each pools as pool (pool.name)}
					<h3 class="mt-2 font-semibold">
						{pool.name}
						{#if pool.overflow}
							<span class="text-sm font-normal text-base-content/60">
								({m.ip_pool_overflow({ pool: pool.overflow })})
							</span>
						{/if}
					</h3>
					<div class="overflow-x-auto">
						<table class="table table-sm">
							<thead>
								<tr>
									<th>{m.ip_address()}</th>
									<th>{m.ip_helo()}</th>
									<th>{m.cluster_node()}</th>
									<th class="text-right">{m.ip_sent_today()}</th>
									<th class="text-right">{m.ip_limit_today()}</th>
									<th class="w-40"></th>
								</tr>
							</thead>
							<tbody>
								{#each pool.addresses as address (address.address)}
									<tr>
										<td class="font-mono">{address.address}</td>
										<td>{address.helo ?? ''}</td>
										<td class="font-mono">{address.node ?? ''}</td>
										<td class="text-right tabular-nums">{address.sent_today}</td>
										<td class="text-right tabular-nums">
											{address.limit_today ?? m.ip_no_limit()}
										</td>
										<td>
											{#if address.limit_today !== null}
												<progress
													class="progress w-full progress-primary"
													value={Math.min(address.sent_today, address.limit_today)}
													max={address.limit_today}
												></progress>
											{/if}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/each}
			{/if}
		</div>
	</section>
{/if}
