<script lang="ts">
	let {
		offset,
		limit,
		total = undefined,
		count,
		onchange
	}: { offset: number; limit: number; total?: number; count: number; onchange: (offset: number) => void } = $props();

	const hasNext = $derived(total !== undefined ? offset + limit < total : count >= limit);
</script>

<div class="flex items-center justify-between gap-3 text-sm">
	<span class="muted">
		{#if count === 0}
			No results
		{:else}
			{offset + 1}–{offset + count}{#if total !== undefined}{` of ${total.toLocaleString()}${total >= 10000 ? '+' : ''}`}{/if}
		{/if}
	</span>
	<div class="flex gap-2">
		<button class="btn btn-sm" disabled={offset === 0} onclick={() => onchange(Math.max(0, offset - limit))}>← Prev</button>
		<button class="btn btn-sm" disabled={!hasNext} onclick={() => onchange(offset + limit)}>Next →</button>
	</div>
</div>
