<script lang="ts">
	import { get, errMsg } from '../api';
	import { debounce, productLabel } from '../format';
	import type { Product } from '../types';

	let {
		onselect,
		autofocus = false,
		placeholder = 'Search a product, e.g. nginx, openssl, react, postgresql…'
	}: { onselect: (p: Product) => void; autofocus?: boolean; placeholder?: string } = $props();

	let q = $state('');
	let results = $state<Product[]>([]);
	let open = $state(false);
	let loading = $state(false);
	let error = $state('');
	let active = $state(0);
	let ctrl: AbortController | null = null;

	const search = debounce(async (term: string) => {
		ctrl?.abort();
		if (term.trim().length < 2) {
			results = [];
			loading = false;
			return;
		}
		ctrl = new AbortController();
		loading = true;
		error = '';
		try {
			results = (await get<Product[]>('/v1/products', { q: term.trim(), limit: 15 }, { signal: ctrl.signal })) ?? [];
			active = 0;
			open = true;
		} catch (e) {
			if ((e as Error).name !== 'AbortError') error = errMsg(e);
		} finally {
			loading = false;
		}
	}, 200);

	function oninput() {
		open = true;
		search(q);
	}

	function choose(p: Product) {
		onselect(p);
		q = '';
		results = [];
		open = false;
	}

	function onkeydown(e: KeyboardEvent) {
		if (!open || results.length === 0) return;
		if (e.key === 'ArrowDown') {
			active = (active + 1) % results.length;
			e.preventDefault();
		} else if (e.key === 'ArrowUp') {
			active = (active - 1 + results.length) % results.length;
			e.preventDefault();
		} else if (e.key === 'Enter') {
			choose(results[active]);
			e.preventDefault();
		} else if (e.key === 'Escape') {
			open = false;
		}
	}
</script>

<div class="relative">
	<!-- svelte-ignore a11y_autofocus -->
	<input
		class="input py-2 text-base"
		type="search"
		bind:value={q}
		{oninput}
		{onkeydown}
		onfocus={() => (open = true)}
		onblur={() => setTimeout(() => (open = false), 150)}
		{placeholder}
		{autofocus}
		autocomplete="off"
		role="combobox"
		aria-expanded={open && results.length > 0}
		aria-controls="product-results"
		aria-autocomplete="list"
	/>
	{#if loading}
		<span class="muted absolute top-2.5 right-3 text-xs">searching…</span>
	{/if}
	{#if open && q.trim().length >= 2 && !loading && (results.length > 0 || error)}
		<ul
			id="product-results"
			role="listbox"
			class="absolute z-20 mt-1 max-h-80 w-full overflow-auto rounded-md border border-zinc-200 bg-white py-1 shadow-lg dark:border-zinc-700 dark:bg-zinc-900"
		>
			{#if error}
				<li class="px-3 py-2 text-sm text-red-600">{error}</li>
			{/if}
			{#each results as p, i (p.id)}
				<li role="option" aria-selected={i === active}>
					<button
						type="button"
						class="flex w-full items-baseline justify-between gap-3 px-3 py-1.5 text-left text-sm {i === active
							? 'bg-zinc-100 dark:bg-zinc-800'
							: ''}"
						onmousedown={(e) => e.preventDefault()}
						onmouseenter={() => (active = i)}
						onclick={() => choose(p)}
					>
						<span class="truncate"><span class="font-medium">{productLabel(p)}</span></span>
						<span class="muted shrink-0 text-xs">{p.ecosystem}</span>
					</button>
				</li>
			{/each}
		</ul>
	{:else if open && q.trim().length >= 2 && !loading && results.length === 0}
		<div class="muted absolute z-20 mt-1 w-full rounded-md border border-zinc-200 bg-white px-3 py-2 text-sm shadow-lg dark:border-zinc-700 dark:bg-zinc-900">
			No products found for “{q}”.
		</div>
	{/if}
</div>
