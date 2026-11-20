<script lang="ts">
	import { toasts } from '../toast.svelte';

	const tone = {
		info: 'border-zinc-200 bg-white text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100',
		success: 'border-green-300 bg-green-50 text-green-900 dark:border-green-800 dark:bg-green-950 dark:text-green-100',
		error: 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-100'
	};
</script>

<div class="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[22rem] max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="polite">
	{#each toasts.items as t (t.id)}
		<div class="pointer-events-auto flex items-start gap-3 rounded-lg border px-3 py-2.5 text-sm shadow-lg {tone[t.kind]}">
			<div class="flex-1">
				{t.message}
				{#if t.href}
					<a href={t.href} class="link ml-1 font-medium" onclick={() => toasts.dismiss(t.id)}>{t.linkText ?? 'Open'}</a>
				{/if}
			</div>
			<button class="muted -mr-1 px-1 hover:text-zinc-900 dark:hover:text-white" aria-label="Dismiss" onclick={() => toasts.dismiss(t.id)}>×</button>
		</div>
	{/each}
</div>
