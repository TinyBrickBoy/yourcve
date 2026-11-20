<script lang="ts">
	import { onMount } from 'svelte';

	let { payload = $bindable('') }: { payload?: string } = $props();

	let el: HTMLElement | undefined = $state();
	let ready = $state(false);

	export function reset() {
		payload = '';
		(el as unknown as { reset?: () => void } | undefined)?.reset?.();
	}

	onMount(() => {
		import('altcha').then(() => (ready = true));
		const handler = (ev: Event) => {
			const d = (ev as CustomEvent<{ state: string; payload?: string }>).detail;
			payload = d?.state === 'verified' && d.payload ? d.payload : '';
		};
		const node = el;
		node?.addEventListener('statechange', handler);
		return () => node?.removeEventListener('statechange', handler);
	});
</script>

<div class="altcha-wrap min-h-[66px]">
	<altcha-widget bind:this={el} challengeurl="/v1/auth/altcha" hidelogo hidefooter></altcha-widget>
	{#if !ready}
		<p class="muted text-xs">Loading spam protection…</p>
	{/if}
</div>

<style>
	.altcha-wrap :global(altcha-widget) {
		--altcha-max-width: 100%;
		--altcha-border-radius: 0.375rem;
		--altcha-color-base: #fff;
		--altcha-color-border: #d4d4d8;
		--altcha-color-text: #18181b;
	}
	@media (prefers-color-scheme: dark) {
		.altcha-wrap :global(altcha-widget) {
			--altcha-color-base: #18181b;
			--altcha-color-border: #3f3f46;
			--altcha-color-text: #f4f4f5;
			--altcha-color-footer-bg: #27272a;
		}
	}
</style>
