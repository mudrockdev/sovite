<script lang="ts">
	import { api } from '#lib/api.ts';
	import { actionLabel, queueActions } from '#lib/labels.ts';
	import { m } from '#lib/paraglide/messages.js';
	import type { MessageAction, QueueName } from '#lib/types.ts';

	let {
		id,
		queue,
		ondone,
		onerror
	}: {
		id: string;
		queue: QueueName;
		ondone: (action: MessageAction) => void;
		onerror: (error: unknown) => void;
	} = $props();

	let busy = $state(false);
	let confirmDelete = $state<HTMLDialogElement>();

	async function act(action: MessageAction) {
		busy = true;
		try {
			await api.act(id, action);
			ondone(action);
		} catch (error) {
			onerror(error);
		} finally {
			busy = false;
		}
	}
</script>

<div class="flex flex-wrap gap-1">
	{#each queueActions[queue] as action (action)}
		<button
			type="button"
			disabled={busy}
			onclick={() => (action === 'delete' ? confirmDelete?.showModal() : act(action))}
			class={['btn btn-xs', action === 'delete' ? 'btn-outline btn-error' : 'btn-soft']}
		>
			{actionLabel[action]()}
		</button>
	{/each}
</div>

<dialog bind:this={confirmDelete} class="modal">
	<div class="modal-box">
		<p class="break-all">{m.confirm_delete({ id })}</p>
		<form method="dialog" class="modal-action">
			<button class="btn btn-ghost">{m.cancel()}</button>
			<button class="btn btn-error" onclick={() => act('delete')}>{m.action_delete()}</button>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop">
		<button>{m.cancel()}</button>
	</form>
</dialog>
