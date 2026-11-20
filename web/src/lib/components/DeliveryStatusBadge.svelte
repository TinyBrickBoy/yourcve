<script lang="ts">
	import Badge from './Badge.svelte';
	import type { DeliveryStatus } from '../types';

	let { status }: { status: DeliveryStatus } = $props();
	const tone = $derived(
		({ sent: 'ok', failed: 'danger', pending: 'info', digest: 'info', suppressed: 'muted' } as const)[status] ?? 'muted'
	);
</script>

<Badge {tone}>{status}</Badge>
