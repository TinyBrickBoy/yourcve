<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { get, post, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { fmtCvss, fmtDate, fmtEpss, truncate } from '#lib/format.js';
	import type { CVESearchResult, CVESummary, SemanticResult } from '#lib/types.js';
	import Badge from '#lib/components/Badge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import Pager from '#lib/components/Pager.svelte';

	const LIMIT = 25;
	const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const;

	// form state, initialised from the URL
	const sp = page.url.searchParams;
	let q = $state(sp.get('q') ?? '');
	let severity = $state<string[]>((sp.get('severity') ?? '').split(',').filter(Boolean));
	let kev = $state(sp.get('kev') === 'true');
	let minEpssPct = $state<number | null>(sp.get('min_epss') ? Number(sp.get('min_epss')) * 100 : null);
	let since = $state((sp.get('since') ?? '').slice(0, 10));
	let semantic = $state(sp.get('semantic') === '1');
	let offset = $state(Number(sp.get('offset') ?? 0) || 0);

	let items = $state<(CVESummary & { distance?: number })[] | null>(null);
	let total = $state<number | undefined>(undefined);
	let loading = $state(false);
	let error = $state('');

	function syncUrl() {
		const u = new URLSearchParams();
		if (q) u.set('q', q);
		if (semantic) u.set('semantic', '1');
		else {
			if (severity.length) u.set('severity', severity.join(','));
			if (kev) u.set('kev', 'true');
			if (minEpssPct) u.set('min_epss', String(minEpssPct / 100));
			if (since) u.set('since', since);
			if (offset) u.set('offset', String(offset));
		}
		const s = u.toString();
		goto(s ? `?${s}` : page.url.pathname, { replace: true, reset: false });
	}

	async function search() {
		loading = true;
		error = '';
		syncUrl();
		try {
			if (semantic) {
				if (!q.trim()) {
					items = [];
					total = undefined;
					return;
				}
				const r = await post<SemanticResult>('/v1/search/semantic', { query: q.trim(), limit: 25 }, { redirectOn401: false });
				items = r?.items ?? [];
				total = undefined;
			} else {
				const r = await get<CVESearchResult>('/v1/cves', {
					q: q.trim(),
					severity: severity.join(','),
					kev: kev || undefined,
					min_epss: minEpssPct ? minEpssPct / 100 : undefined,
					since: since ? `${since}T00:00:00Z` : undefined,
					limit: LIMIT,
					offset
				});
				items = r?.items ?? [];
				total = r?.total ?? 0;
			}
		} catch (e) {
			const msg = errMsg(e);
			error = semantic && (e as { status?: number }).status === 401 ? 'Sign in to use semantic search.' : msg;
			items = [];
		} finally {
			loading = false;
		}
	}

	function submit(e: SubmitEvent) {
		e.preventDefault();
		// a CVE id jumps straight to the detail page
		if (/^cve-\d{4}-\d{4,}$/i.test(q.trim())) {
			goto(`/cves/${q.trim().toUpperCase()}`);
			return;
		}
		offset = 0;
		search();
	}

	function toggleSev(s: string) {
		severity = severity.includes(s) ? severity.filter((x) => x !== s) : [...severity, s];
		offset = 0;
		search();
	}

	onMount(search);
</script>

<svelte:head><title>CVEs · yourcve</title></svelte:head>

<h1 class="h1">CVE search</h1>

<form class="card mt-6 space-y-4 p-4" onsubmit={submit}>
	<div class="flex gap-2">
		<input
			class="input py-2 text-base"
			type="search"
			bind:value={q}
			placeholder={semantic ? 'Describe what you are looking for, e.g. “remote code execution in image parsers”' : 'Search text or a CVE id, e.g. CVE-2024-6387'}
		/>
		<button class="btn btn-primary shrink-0 px-4">Search</button>
	</div>

	{#if session.config.ai_enabled}
		<label class="flex items-center gap-2 text-sm">
			<input
				type="checkbox"
				bind:checked={semantic}
				onchange={() => {
					offset = 0;
					search();
				}}
			/>
			Semantic search <Badge tone="ai">AI</Badge>
			<span class="muted text-xs">finds CVEs by meaning instead of keywords</span>
		</label>
	{/if}

	{#if !semantic}
		<div class="flex flex-wrap items-end gap-x-6 gap-y-3">
			<div>
				<span class="label">Severity</span>
				<div class="flex flex-wrap gap-1">
					{#each SEVERITIES as s (s)}
						<button
							type="button"
							class="btn btn-sm capitalize {severity.includes(s) ? 'btn-primary' : ''}"
							aria-pressed={severity.includes(s)}
							onclick={() => toggleSev(s)}>{s}</button
						>
					{/each}
				</div>
			</div>
			<label class="flex items-center gap-2 pb-1 text-sm">
				<input
					type="checkbox"
					bind:checked={kev}
					onchange={() => {
						offset = 0;
						search();
					}}
				/> Known exploited (KEV) only
			</label>
			<div>
				<label class="label" for="min-epss">Min EPSS %</label>
				<input id="min-epss" class="input w-24" type="number" min="0" max="100" step="0.1" bind:value={minEpssPct} />
			</div>
			<div>
				<label class="label" for="since">Published since</label>
				<input id="since" class="input w-40" type="date" bind:value={since} />
			</div>
			<button class="btn btn-sm mb-0.5">Apply</button>
		</div>
	{/if}
</form>

{#if error}<p class="alert-error mt-4">{error}</p>{/if}

<div class="mt-6">
	{#if items === null}
		<p class="muted text-sm">Loading…</p>
	{:else}
		{#if !semantic}
			<Pager {offset} limit={LIMIT} {total} count={items.length} onchange={(o) => ((offset = o), search(), window.scrollTo(0, 0))} />
		{/if}
		<ul class="mt-3 space-y-2 {loading ? 'opacity-60' : ''}">
			{#each items as c (c.id)}
				<li class="card p-4">
					<div class="flex flex-wrap items-center gap-2">
						<a href="/cves/{c.id}" class="link font-mono text-sm font-semibold">{c.id}</a>
						<SeverityBadge severity={c.severity} cvss={c.cvss} />
						{#if c.kev}<Badge tone="kev" title="Known Exploited Vulnerability (CISA KEV)">KEV</Badge>{/if}
						{#if c.category}<Badge tone="ai" title="AI generated category">{c.category}</Badge>{/if}
						<span class="muted ml-auto text-xs">
							EPSS {fmtEpss(c.epss)} · published {fmtDate(c.published)}
							{#if c.distance !== undefined}· distance {c.distance.toFixed(3)}{/if}
						</span>
					</div>
					<p class="mt-1.5 text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">{truncate(c.description, 320)}</p>
				</li>
			{:else}
				<li class="muted text-sm">{semantic && !q.trim() ? 'Enter a query to search.' : 'No CVEs match these filters.'}</li>
			{/each}
		</ul>
		{#if !semantic && items.length > 0}
			<div class="mt-4">
				<Pager {offset} limit={LIMIT} {total} count={items.length} onchange={(o) => ((offset = o), search(), window.scrollTo(0, 0))} />
			</div>
		{/if}
	{/if}
</div>
