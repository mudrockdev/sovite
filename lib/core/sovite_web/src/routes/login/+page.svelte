<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { ApiError, api } from '#lib/api.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { session } from '#lib/session.svelte.ts';

	let token = $state('');
	let checking = $state(false);
	let failure = $state<string | null>(null);

	function describe(error: unknown): string {
		if (error instanceof ApiError && error.status === 401) return m.login_invalid();
		if (error instanceof ApiError && error.status === 429) return m.login_banned();
		return m.login_failed({ error: error instanceof Error ? error.message : String(error) });
	}

	async function signIn(event: SubmitEvent) {
		event.preventDefault();
		const value = token.trim();
		if (!value) return;

		checking = true;
		failure = null;

		try {
			await api.check(value);
			session.signIn(value);
			token = '';
			await goto(resolve('/'));
		} catch (error) {
			failure = describe(error);
		} finally {
			checking = false;
		}
	}
</script>

<div class="mx-auto mt-12 max-w-md">
	<form onsubmit={signIn} class="card bg-base-100 shadow-sm">
		<div class="card-body">
			<h1 class="card-title text-2xl">{m.login_title()}</h1>
			<p class="text-sm text-base-content/70">
				{m.login_intro({ path: '/var/lib/sovite/admin.token' })}
			</p>

			<fieldset class="fieldset">
				<legend class="fieldset-legend">{m.login_token()}</legend>
				<input
					type="password"
					bind:value={token}
					required
					autocomplete="current-password"
					spellcheck="false"
					class="input w-full font-mono"
				/>
				<p class="label text-wrap">{m.login_note()}</p>
			</fieldset>

			{#if failure}
				<div role="alert" class="alert alert-soft alert-error">
					<span>{failure}</span>
				</div>
			{/if}

			<div class="card-actions">
				<button type="submit" disabled={checking} class="btn w-full btn-primary">
					{#if checking}
						<span class="loading loading-sm loading-spinner"></span>
						{m.login_checking()}
					{:else}
						{m.login_submit()}
					{/if}
				</button>
			</div>
		</div>
	</form>
</div>
