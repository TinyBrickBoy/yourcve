<script lang="ts">
	import type { Severity } from '../types';

	let { severity, cvss = undefined }: { severity: Severity | null | undefined; cvss?: number | null } = $props();

	const styles: Record<string, string> = {
		critical: 'bg-red-600 text-white dark:bg-red-600',
		high: 'bg-orange-500 text-white dark:bg-orange-600',
		medium: 'bg-yellow-300 text-yellow-950 dark:bg-yellow-400',
		low: 'bg-sky-100 text-sky-900 dark:bg-sky-900/60 dark:text-sky-200',
		none: 'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300',
		unknown: 'bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400'
	};
	const sev = $derived(severity ?? 'unknown');
</script>

<span
	class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] leading-4 font-semibold tracking-wide whitespace-nowrap uppercase {styles[
		sev
	] ?? styles.unknown}"
	title="Severity: {sev}{cvss != null ? ` (CVSS ${cvss.toFixed(1)})` : ''}"
>
	{sev}{#if cvss != null}<span class="font-mono font-medium normal-case opacity-90">{cvss.toFixed(1)}</span>{/if}
</span>
