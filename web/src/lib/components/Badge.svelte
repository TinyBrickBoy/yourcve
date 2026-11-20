<script lang="ts">
	import type { Snippet } from 'svelte';

	type Tone = 'kev' | 'unconfirmed' | 'ai' | 'ok' | 'warn' | 'muted' | 'info' | 'danger';
	let { tone = 'muted', title = undefined, children }: { tone?: Tone; title?: string; children: Snippet } =
		$props();

	const styles: Record<Tone, string> = {
		kev: 'bg-rose-950 text-rose-50 ring-rose-950 dark:bg-rose-500/20 dark:text-rose-200 dark:ring-rose-500/50',
		unconfirmed:
			'bg-amber-50 text-amber-800 ring-amber-300 ring-dashed dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-500/40',
		ai: 'bg-violet-50 text-violet-700 ring-violet-200 dark:bg-violet-500/10 dark:text-violet-300 dark:ring-violet-500/30',
		ok: 'bg-green-50 text-green-700 ring-green-200 dark:bg-green-500/10 dark:text-green-300 dark:ring-green-500/30',
		warn: 'bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-500/30',
		danger: 'bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-500/30',
		info: 'bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/10 dark:text-blue-300 dark:ring-blue-500/30',
		muted: 'bg-zinc-50 text-zinc-600 ring-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:ring-zinc-700'
	};
</script>

<span
	{title}
	class="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] leading-4 font-medium whitespace-nowrap ring-1 ring-inset {styles[
		tone
	]}"
>
	{@render children()}
</span>
