<script lang="ts">
	import { api } from '#lib/api.ts';
	import ErrorBanner from '#lib/components/ErrorBanner.svelte';
	import { m } from '#lib/paraglide/messages.js';
	import type { RouteInfo, RouteRecipient } from '#lib/types.ts';

	let address = $state('');
	let sender = $state('');
	let result = $state<RouteInfo | null>(null);
	let error = $state<unknown>(null);
	let busy = $state(false);

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		try {
			result = await api.route(address.trim(), sender.trim());
			error = null;
		} catch (e) {
			error = e;
			result = null;
		} finally {
			busy = false;
		}
	}

	function describe(recipient: RouteRecipient): string {
		switch (recipient.result) {
			case 'deliver':
				return recipient.transport === 'local' || recipient.transport === 'mailbox'
					? m.result_deliver({ transport: recipient.transport })
					: m.result_deliver_to({
							transport: recipient.transport ?? '',
							nexthop: recipient.nexthop ?? ''
						});
			case 'defer':
				return `${m.result_defer()}: ${recipient.status} ${recipient.text}`;
			case 'fail':
				return `${m.result_fail()}: ${recipient.status} ${recipient.text}`;
			default:
				return `${m.result_discard()}: ${recipient.text}`;
		}
	}

	const resultColor: Record<RouteRecipient['result'], string> = {
		deliver: 'text-success',
		defer: 'text-warning',
		fail: 'text-error',
		discard: 'text-base-content/60'
	};
</script>

<h1 class="mb-2 text-2xl font-semibold">{m.route_title()}</h1>
<p class="mb-6 max-w-3xl text-sm text-base-content/70">{m.route_intro()}</p>

<form onsubmit={submit} class="card mb-6 bg-base-100 shadow-sm">
	<div class="card-body grid gap-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
		<fieldset class="fieldset">
			<legend class="fieldset-legend">{m.address()}</legend>
			<input
				type="text"
				bind:value={address}
				required
				spellcheck="false"
				placeholder="alice@example.com"
				class="input w-full"
			/>
		</fieldset>
		<fieldset class="fieldset">
			<legend class="fieldset-legend">{m.sender_optional()}</legend>
			<input type="text" bind:value={sender} spellcheck="false" class="input w-full" />
		</fieldset>
		<button type="submit" disabled={busy} class="btn btn-primary">{m.route_submit()}</button>
	</div>
</form>

{#if error}
	<ErrorBanner {error} />
{/if}

{#if result}
	<section class="card bg-base-100 shadow-sm">
		<div class="card-body">
			<h2 class="card-title font-mono break-all">{result.address}</h2>

			{#if result.error}
				<div role="alert" class="alert alert-soft alert-error"><span>{result.error}</span></div>
			{:else}
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
					{#if result.rewritten}
						<dt></dt>
						<dd>{m.rewritten_to({ address: result.rewritten })}</dd>
					{/if}
					<dt class="text-base-content/60">{m.domain()}</dt>
					<dd>{result.domain}</dd>
					<dt class="text-base-content/60">{m.domain_class()}</dt>
					<dd><span class="badge badge-outline badge-sm">{result.class}</span></dd>
					{#if result.expanded}
						<dt class="text-base-content/60">{m.expands_to()}</dt>
						<dd class="break-all">{result.expanded.join(', ')}</dd>
					{/if}
				</dl>
			{/if}

			<ul class="list mt-2 rounded-box border border-base-300">
				{#each result.recipients as recipient (recipient.address)}
					<li class="list-row block text-sm">
						<div class="font-mono break-all">{recipient.address}</div>
						<div class={resultColor[recipient.result]}>{describe(recipient)}</div>
						{#if recipient.source && Object.keys(recipient.source).length > 0}
							<div class="text-xs text-base-content/60">
								{m.source()}: {Object.values(recipient.source).join(', ')}
							</div>
						{/if}
						{#if recipient.login}
							<div class="text-xs text-base-content/60">{m.login()}: {recipient.login}</div>
						{/if}
					</li>
				{/each}
			</ul>
		</div>
	</section>
{/if}
