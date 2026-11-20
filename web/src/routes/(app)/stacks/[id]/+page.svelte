<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { get, post, patch, del, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { live } from '#lib/events.svelte.js';
	import { productLabel } from '#lib/format.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { ImportResult, Product, Stack, StackCVE, StackItem } from '#lib/types.js';
	import ProductSearch from '#lib/components/ProductSearch.svelte';
	import ImportDrop from '#lib/components/ImportDrop.svelte';
	import StackCves from '#lib/components/StackCves.svelte';
	import StackRules from '#lib/components/StackRules.svelte';

	type Tab = 'products' | 'cves' | 'notifications';

	const id = $derived(Number(page.params.id));
	const tab = $derived<Tab>(
		(['products', 'cves', 'notifications'] as const).find((t) => t === page.url.searchParams.get('tab')) ?? 'products'
	);

	let stack = $state<Stack | null>(null);
	let notFound = $state('');
	let cves = $state<StackCVE[] | null>(null);
	let cvesLoading = $state(false);
	let includeResolved = $state(false);
	let ruleCount = $state<number | null>(null);

	// add-product flow
	let picked = $state<Product | null>(null);
	let version = $state('');
	let adding = $state(false);
	let versionInput: HTMLInputElement | undefined = $state();

	// rename
	let renaming = $state(false);
	let newName = $state('');

	const items = $derived(stack?.items ?? []);
	const openCount = $derived(cves?.filter((c) => c.status === 'open').length ?? stack?.open_cves ?? 0);

	async function loadStack() {
		try {
			stack = await get<Stack>(`/v1/stacks/${id}`);
		} catch (e) {
			notFound = errMsg(e);
		}
	}

	let cvesReq = 0;
	async function loadCves() {
		const req = ++cvesReq;
		cvesLoading = true;
		try {
			const r = await get<StackCVE[]>(`/v1/stacks/${id}/cves`, { include_resolved: includeResolved });
			if (req === cvesReq) cves = r ?? [];
		} catch (e) {
			if (req === cvesReq) toast.error(errMsg(e));
		} finally {
			if (req === cvesReq) cvesLoading = false;
		}
	}

	// Matching may run asynchronously on the server: refresh now and once more shortly after.
	let laterTimer: ReturnType<typeof setTimeout> | undefined;
	function refreshCvesSoon() {
		loadCves();
		clearTimeout(laterTimer);
		laterTimer = setTimeout(loadCves, 2500);
	}

	$effect(() => {
		void id;
		stack = null;
		cves = null;
		notFound = '';
		loadStack();
	});

	$effect(() => {
		void id;
		void includeResolved;
		loadCves();
	});

	$effect(() => {
		const off = live.onMatch((m) => {
			if (m.stack_id === id) loadCves();
		});
		return () => {
			off();
			clearTimeout(laterTimer);
		};
	});

	function setTab(t: Tab) {
		const u = new URL(page.url.href);
		if (t === 'products') u.searchParams.delete('tab');
		else u.searchParams.set('tab', t);
		goto(u.pathname + u.search, { replace: true, reset: false });
	}

	function pick(p: Product) {
		picked = p;
		version = '';
		setTimeout(() => versionInput?.focus(), 0);
	}

	async function addItem(e?: SubmitEvent) {
		e?.preventDefault();
		if (!picked || !stack) return;
		adding = true;
		try {
			const item = await post<StackItem>(`/v1/stacks/${id}/items`, { product_id: picked.id, version: version.trim() });
			stack.items = [...(stack.items ?? []), item];
			stack.item_count = stack.items.length;
			toast.success(`Added ${productLabel(item?.product ?? picked)}`);
			picked = null;
			version = '';
			refreshCvesSoon();
		} catch (e) {
			toast.error(errMsg(e));
		} finally {
			adding = false;
		}
	}

	async function updateVersion(item: StackItem, v: string) {
		const nv = v.trim();
		if (nv === (item.version === '*' ? '' : item.version)) return;
		try {
			const updated = await patch<StackItem>(`/v1/stacks/${id}/items/${item.id}`, { version: nv });
			item.version = updated?.version ?? (nv || '*');
			refreshCvesSoon();
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	async function removeItem(item: StackItem) {
		if (!stack) return;
		try {
			await del(`/v1/stacks/${id}/items/${item.id}`);
			stack.items = (stack.items ?? []).filter((i) => i.id !== item.id);
			stack.item_count = stack.items.length;
			refreshCvesSoon();
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	async function onimported(r: ImportResult) {
		if (r.added > 0) {
			await loadStack();
			refreshCvesSoon();
		}
	}

	async function rename(e: SubmitEvent) {
		e.preventDefault();
		if (!stack || !newName.trim()) return;
		try {
			const s = await patch<Stack>(`/v1/stacks/${id}`, { name: newName.trim() });
			stack.name = s?.name ?? newName.trim();
			renaming = false;
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	async function remove() {
		if (!stack) return;
		if (!confirm(`Delete stack “${stack.name}” with all its products, assessments and rules?`)) return;
		try {
			await del(`/v1/stacks/${id}`);
			session.refreshMe();
			toast.success('Stack deleted');
			await goto('/stacks');
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	const tabClass = (t: Tab) =>
		`-mb-px border-b-2 px-3 py-2 text-sm ${
			tab === t
				? 'border-zinc-900 font-medium text-zinc-900 dark:border-white dark:text-white'
				: 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
		}`;
</script>

<svelte:head><title>{stack?.name ?? 'Stack'} · yourcve</title></svelte:head>

<a href="/stacks" class="muted text-sm hover:underline">← Stacks</a>

{#if notFound}
	<p class="alert-error mt-4">{notFound}</p>
{:else if !stack}
	<p class="muted mt-4 text-sm">Loading…</p>
{:else}
	<div class="mt-2 flex flex-wrap items-center justify-between gap-3">
		{#if renaming}
			<form class="flex gap-2" onsubmit={rename}>
				<!-- svelte-ignore a11y_autofocus -->
				<input class="input text-lg" bind:value={newName} maxlength="100" autofocus required />
				<button class="btn btn-primary">Save</button>
				<button type="button" class="btn" onclick={() => (renaming = false)}>Cancel</button>
			</form>
		{:else}
			<h1 class="h1">{stack.name}</h1>
			<div class="flex gap-2">
				<button class="btn btn-sm" onclick={() => ((newName = stack!.name), (renaming = true))}>Rename</button>
				<button class="btn btn-sm btn-danger" onclick={remove}>Delete</button>
			</div>
		{/if}
	</div>

	<div class="mt-6 flex gap-1 border-b border-zinc-200 dark:border-zinc-800" role="tablist">
		<button role="tab" aria-selected={tab === 'products'} class={tabClass('products')} onclick={() => setTab('products')}>
			Products <span class="muted ml-1 text-xs">{items.length}</span>
		</button>
		<button role="tab" aria-selected={tab === 'cves'} class={tabClass('cves')} onclick={() => setTab('cves')}>
			CVEs
			{#if cves !== null}
				<span
					class="ml-1 rounded-full px-1.5 text-xs {openCount > 0
						? 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300'
						: 'muted'}">{openCount}</span
				>
			{/if}
		</button>
		<button role="tab" aria-selected={tab === 'notifications'} class={tabClass('notifications')} onclick={() => setTab('notifications')}>
			Notifications {#if ruleCount !== null}<span class="muted ml-1 text-xs">{ruleCount}</span>{/if}
		</button>
	</div>

	<div class="mt-6">
		{#if tab === 'products'}
			{#if items.length > 0 && cves !== null}
				<button
					class="mb-6 flex w-full items-center justify-between gap-3 rounded-lg border px-4 py-3 text-left text-sm {openCount > 0
						? 'border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/40'
						: 'border-green-200 bg-green-50 dark:border-green-900 dark:bg-green-950/40'}"
					onclick={() => setTab('cves')}
				>
					<span>
						{#if openCount > 0}
							<strong>{openCount} open CVE{openCount === 1 ? '' : 's'}</strong> affect{openCount === 1 ? 's' : ''} this stack.
						{:else}
							<strong>No open CVEs</strong> affect this stack right now.
						{/if}
					</span>
					<span class="font-medium">View CVEs →</span>
				</button>
			{/if}

			<section class="card p-4">
				<h2 class="font-medium">{items.length === 0 ? 'Step 1 – add the software you run' : 'Add a product'}</h2>
				<p class="muted mt-0.5 mb-3 text-sm">Search, pick a product, then optionally enter the version you use.</p>
				{#if picked}
					<form class="flex flex-wrap items-end gap-2" onsubmit={addItem}>
						<div class="min-w-48 flex-1">
							<span class="label">Product</span>
							<div class="flex items-center gap-2 rounded-md border border-zinc-300 bg-zinc-50 px-2.5 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-800">
								<span class="font-medium">{productLabel(picked)}</span>
								<span class="muted text-xs">{picked.ecosystem}</span>
							</div>
						</div>
						<div class="w-48">
							<label class="label" for="ver">Version (empty = all versions)</label>
							<input id="ver" class="input font-mono" bind:this={versionInput} bind:value={version} placeholder="e.g. 1.24.0" />
						</div>
						<button class="btn btn-primary" disabled={adding}>{adding ? 'Adding…' : 'Add to stack'}</button>
						<button type="button" class="btn" onclick={() => (picked = null)}>Cancel</button>
					</form>
				{:else}
					<ProductSearch onselect={pick} autofocus={items.length === 0} />
				{/if}

				<div class="mt-4">
					<ImportDrop stackId={id} {onimported} />
				</div>
			</section>

			{#if items.length > 0}
				<section class="card mt-6 overflow-x-auto">
					<table class="table">
						<thead><tr><th>Product</th><th>Ecosystem</th><th>Version</th><th></th></tr></thead>
						<tbody>
							{#each items as item (item.id)}
								<tr>
									<td class="font-medium">{productLabel(item.product)}</td>
									<td class="muted text-xs">{item.product.ecosystem}</td>
									<td>
										<input
											class="input w-40 py-1 font-mono text-xs"
											value={item.version === '*' ? '' : item.version}
											placeholder="all versions"
											aria-label="Version of {item.product.name}"
											onchange={(e) => updateVersion(item, (e.currentTarget as HTMLInputElement).value)}
											onkeydown={(e) => e.key === 'Enter' && (e.currentTarget as HTMLInputElement).blur()}
										/>
									</td>
									<td class="text-right">
										<button class="btn btn-sm btn-ghost text-red-600 dark:text-red-400" onclick={() => removeItem(item)}>Remove</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</section>
			{/if}
		{:else if tab === 'cves'}
			{#if items.length === 0}
				<p class="muted text-sm">
					This stack has no products yet. <button class="link" onclick={() => setTab('products')}>Add products</button> to see matching CVEs.
				</p>
			{:else}
				<StackCves stackId={id} {cves} loading={cvesLoading} bind:includeResolved onchanged={() => {}} />
			{/if}
		{:else}
			<StackRules stackId={id} oncount={(n) => (ruleCount = n)} />
		{/if}
	</div>
{/if}
