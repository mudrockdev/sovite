<script lang="ts">
	import { queueLabel } from '#lib/labels.ts';
	import type { QueueName } from '#lib/types.ts';

	let { queue }: { queue: QueueName } = $props();

	const colors: Record<QueueName, string> = {
		incoming: 'badge-info',
		active: 'badge-success',
		deferred: 'badge-warning',
		hold: 'badge-neutral',
		corrupt: 'badge-error'
	};
</script>

<span class="badge badge-soft badge-sm {colors[queue]}">{queueLabel[queue]()}</span>
