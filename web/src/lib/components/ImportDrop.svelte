<script lang="ts">
	import { api, errMsg } from '../api';
	import type { ImportResult } from '../types';

	let { stackId, onimported }: { stackId: number; onimported: (r: ImportResult) => void } = $props();

	let over = $state(false);
	let busy = $state(false);
	let error = $state('');
	let result = $state<ImportResult | null>(null);
	let fileInput: HTMLInputElement | undefined = $state();

	async function upload(file: File) {
		busy = true;
		error = '';
		result = null;
		try {
			const fd = new FormData();
			fd.append('file', file, file.name);
			const r = await api<ImportResult>('POST', `/v1/stacks/${stackId}/import`, fd);
			result = r;
			onimported(r);
		} catch (e) {
			error = errMsg(e);
		} finally {
			busy = false;
			if (fileInput) fileInput.value = '';
		}
	}

	function ondrop(e: DragEvent) {
		e.preventDefault();
		over = false;
		const f = e.dataTransfer?.files?.[0];
		if (f) upload(f);
	}
</script>

<div
	role="region"
	aria-label="Import file"
	class="rounded-lg border-2 border-dashed px-4 py-5 text-center text-sm transition {over
		? 'border-blue-500 bg-blue-50 dark:bg-blue-950/30'
		: 'border-zinc-300 dark:border-zinc-700'}"
	ondragover={(e) => {
		e.preventDefault();
		over = true;
	}}
	ondragleave={() => (over = false)}
	{ondrop}
>
	{#if busy}
		<p>Importing…</p>
	{:else}
		<p>
			Drop a <code>package.json</code>, <code>go.mod</code>, <code>requirements.txt</code>, <code>docker-compose.yml</code>, CycloneDX or
			SPDX JSON here, or
			<button type="button" class="link font-medium" onclick={() => fileInput?.click()}>choose a file</button>.
		</p>
	{/if}
	<input
		bind:this={fileInput}
		type="file"
		class="hidden"
		accept=".json,.mod,.txt,.yml,.yaml"
		onchange={(e) => {
			const f = (e.currentTarget as HTMLInputElement).files?.[0];
			if (f) upload(f);
		}}
	/>
</div>

{#if error}<p class="alert-error mt-2">{error}</p>{/if}
{#if result}
	<div class="alert-ok mt-2">
		Added {result.added} product{result.added === 1 ? '' : 's'}.
		{#if result.skipped && result.skipped.length > 0}
			<details class="mt-1">
				<summary class="cursor-pointer">{result.skipped.length} skipped (not found or duplicate)</summary>
				<p class="mt-1 font-mono text-xs break-words">{result.skipped.join(', ')}</p>
			</details>
		{/if}
	</div>
{/if}
