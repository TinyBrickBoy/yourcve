<script lang="ts">
	import { goto } from '$app/navigation';
	import { session } from '#lib/session.svelte.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	// Protected area: redirect to /login when there is no session.
	$effect(() => {
		if (session.loaded && !session.me) goto('/login', { replace: true });
	});
</script>

{#if session.me}
	{@render children()}
{/if}
