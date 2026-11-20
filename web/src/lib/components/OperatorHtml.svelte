<script lang="ts">
	import { session } from '../session.svelte';

	let { title, field }: { title: string; field: 'privacy_html' | 'imprint_html' } = $props();
	const html = $derived(session.config[field]?.trim() ?? '');
	const what = $derived(field === 'privacy_html' ? 'a privacy policy' : 'an imprint');
</script>

<svelte:head><title>{title} · yourcve</title></svelte:head>

<article class="prose-operator max-w-3xl">
	<h1 class="h1">{title}</h1>
	{#if html}
		<!-- operator supplied content from the instance configuration -->
		<div class="mt-6 text-sm leading-relaxed">{@html html}</div>
	{:else}
		<p class="muted mt-6 text-sm">The operator has not provided {what} for this instance yet.</p>
	{/if}
</article>

<style>
	.prose-operator :global(h2) {
		margin-top: 1.5rem;
		font-size: 1.125rem;
		font-weight: 600;
	}
	.prose-operator :global(h3) {
		margin-top: 1.25rem;
		font-weight: 600;
	}
	.prose-operator :global(p),
	.prose-operator :global(ul),
	.prose-operator :global(ol) {
		margin-top: 0.75rem;
	}
	.prose-operator :global(ul) {
		list-style: disc;
		padding-left: 1.25rem;
	}
	.prose-operator :global(ol) {
		list-style: decimal;
		padding-left: 1.25rem;
	}
	.prose-operator :global(a) {
		text-decoration: underline;
	}
</style>
