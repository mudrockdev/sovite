<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale, locales, setLocale } from '#lib/paraglide/runtime.js';
	import { session } from '#lib/session.svelte.ts';
	import favicon from '#lib/assets/favicon.svg';
	import './layout.css';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const onLogin = $derived(page.route.id === '/login');

	const nav = [
		{ href: resolve('/'), id: '/', label: m.nav_overview },
		{ href: resolve('/queue'), id: '/queue', label: m.nav_queue },
		{ href: resolve('/route'), id: '/route', label: m.nav_route },
		{ href: resolve('/trace'), id: '/trace', label: m.nav_trace },
		{ href: resolve('/config'), id: '/config', label: m.nav_config }
	];

	function current(id: string): boolean {
		const route = page.route.id ?? '';
		return id === '/' ? route === '/' : route.startsWith(id);
	}

	// Pages need the token; the sign-in page does not.
	$effect(() => {
		if (!session.token && !onLogin) goto(resolve('/login'), { replaceState: true });
	});

	$effect(() => {
		document.documentElement.lang = getLocale();
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>{m.app_name()}</title>
</svelte:head>

<div class="min-h-screen bg-base-200">
	<header class="navbar gap-2 border-b border-base-300 bg-base-100 px-4">
		<div class="navbar-start w-auto">
			<a href={resolve('/')} class="btn btn-ghost text-lg">{m.app_name()}</a>
		</div>

		<nav aria-label={m.nav_label()} class="navbar-center flex-1 justify-start">
			{#if session.token && !onLogin}
				<ul class="menu menu-horizontal gap-1 px-1">
					{#each nav as item (item.id)}
						<li>
							<a
								href={item.href}
								class={{ 'menu-active': current(item.id) }}
								aria-current={current(item.id) ? 'page' : undefined}
							>
								{item.label()}
							</a>
						</li>
					{/each}
				</ul>
			{/if}
		</nav>

		<div class="navbar-end w-auto gap-2">
			<div class="join" role="group" aria-label={m.language()}>
				{#each locales as locale (locale)}
					<button
						type="button"
						onclick={() => setLocale(locale)}
						aria-pressed={getLocale() === locale}
						class={['btn join-item uppercase btn-sm', getLocale() === locale && 'btn-active']}
					>
						{locale}
					</button>
				{/each}
			</div>

			{#if session.token && !onLogin}
				<button type="button" onclick={() => session.signOut()} class="btn btn-outline btn-sm">
					{m.sign_out()}
				</button>
			{/if}
		</div>
	</header>

	<main class="mx-auto max-w-6xl px-4 py-6">
		{#if session.token || onLogin}
			{@render children()}
		{/if}
	</main>
</div>
