<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';

	let { error }: { error: unknown } = $props();

	const message = $derived(error instanceof Error ? error.message : String(error));
</script>

<div role="alert" class="alert alert-soft alert-error">
	<span>{m.error_generic({ error: message })}</span>
</div>
