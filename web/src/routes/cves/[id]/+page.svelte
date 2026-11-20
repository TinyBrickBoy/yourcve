<script lang="ts">
	import { page } from '$app/state';
	import { get, errMsg } from '#lib/api.js';
	import { fmtCvss, fmtDate, fmtEpss, productLabel } from '#lib/format.js';
	import type { Affect, CVEDetail } from '#lib/types.js';
	import Badge from '#lib/components/Badge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';

	let cve = $state<CVEDetail | null>(null);
	let error = $state('');

	$effect(() => {
		const id = page.params.id ?? '';
		cve = null;
		error = '';
		get<CVEDetail>(`/v1/cves/${encodeURIComponent(id)}`, undefined, { redirectOn401: false })
			.then((c) => (cve = c))
			.catch((e) => (error = (e as { status?: number }).status === 404 ? `${id} is not known (yet).` : errMsg(e)));
	});

	function range(a: Affect): string {
		const parts: string[] = [];
		if (a.version_start_including) parts.push(`≥ ${a.version_start_including}`);
		if (a.version_start_excluding) parts.push(`> ${a.version_start_excluding}`);
		if (a.version_end_including) parts.push(`≤ ${a.version_end_including}`);
		if (a.version_end_excluding) parts.push(`< ${a.version_end_excluding}`);
		if (a.versions?.length) parts.push(a.versions.join(', '));
		return parts.length ? parts.join(' and ') : 'all versions';
	}

	function hostOf(u: string): string {
		try {
			return new URL(u).host;
		} catch {
			return '';
		}
	}
</script>

<svelte:head><title>{page.params.id} · yourcve</title></svelte:head>

<a href="/cves" class="muted text-sm hover:underline">← CVE search</a>

{#if error}
	<p class="alert-error mt-4">{error}</p>
{:else if !cve}
	<p class="muted mt-4 text-sm">Loading…</p>
{:else}
	<header class="mt-2">
		<div class="flex flex-wrap items-center gap-2">
			<h1 class="h1 font-mono">{cve.id}</h1>
			<SeverityBadge severity={cve.severity} cvss={cve.cvss} />
			{#if cve.kev}<Badge tone="kev" title="Known Exploited Vulnerability (CISA KEV)">KEV</Badge>{/if}
			{#if cve.category}<Badge tone="ai" title="AI generated category">{cve.category}</Badge>{/if}
		</div>
		{#if cve.title}<p class="mt-1 text-lg">{cve.title}</p>{/if}
	</header>

	<dl class="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
		<div class="card p-3">
			<dt class="muted text-xs">CVSS {cve.cvss_version ?? ''}</dt>
			<dd class="mt-1 text-xl font-semibold tabular-nums">{fmtCvss(cve.cvss)}</dd>
		</div>
		<div class="card p-3">
			<dt class="muted text-xs">EPSS (30 day exploit probability)</dt>
			<dd class="mt-1 text-xl font-semibold tabular-nums">
				{fmtEpss(cve.epss)}
				{#if cve.epss_percentile != null}<span class="muted text-xs font-normal">{Math.round(cve.epss_percentile * 100)}th pct.</span>{/if}
			</dd>
		</div>
		<div class="card p-3">
			<dt class="muted text-xs">Published</dt>
			<dd class="mt-1 text-sm font-medium">{fmtDate(cve.published)}</dd>
		</div>
		<div class="card p-3">
			<dt class="muted text-xs">Last modified</dt>
			<dd class="mt-1 text-sm font-medium">{fmtDate(cve.modified)}</dd>
		</div>
	</dl>

	{#if cve.kev}
		<section class="mt-6 rounded-lg border border-rose-300 bg-rose-50 p-4 text-sm dark:border-rose-900 dark:bg-rose-950/40">
			<h2 class="font-semibold text-rose-900 dark:text-rose-200">Known exploited vulnerability (CISA KEV)</h2>
			<dl class="mt-2 grid gap-x-6 gap-y-1 sm:grid-cols-[auto_1fr]">
				<dt class="muted">Added</dt><dd>{fmtDate(cve.kev_added)}</dd>
				{#if cve.kev_due}<dt class="muted">Due date</dt><dd>{fmtDate(cve.kev_due)}</dd>{/if}
				{#if cve.kev_action}<dt class="muted">Required action</dt><dd>{cve.kev_action}</dd>{/if}
			</dl>
		</section>
	{/if}

	{#if cve.summary}
		<section class="mt-6 rounded-lg border border-violet-200 bg-violet-50/60 p-4 dark:border-violet-900 dark:bg-violet-950/30">
			<div class="flex items-center gap-2">
				<h2 class="font-semibold">Summary</h2>
				<Badge tone="ai">AI generated</Badge>
				{#if cve.ai_model}<span class="muted font-mono text-xs">{cve.ai_model}</span>{/if}
			</div>
			<p class="mt-2 text-sm leading-relaxed whitespace-pre-line">{cve.summary}</p>
		</section>
	{/if}

	<section class="mt-6">
		<h2 class="h2">Description</h2>
		<p class="mt-2 text-sm leading-relaxed whitespace-pre-line">{cve.description}</p>
		<dl class="muted mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs">
			{#if cve.cvss_vector}<div><dt class="inline">Vector:</dt> <dd class="inline font-mono">{cve.cvss_vector}</dd></div>{/if}
			{#if cve.cwe?.length}
				<div>
					<dt class="inline">CWE:</dt>
					<dd class="inline">
						{#each cve.cwe as w, i (w)}{i ? ', ' : ''}<a
								class="link"
								href="https://cwe.mitre.org/data/definitions/{w.replace(/^CWE-/i, '')}.html"
								target="_blank"
								rel="noopener noreferrer">{w}</a
							>{/each}
					</dd>
				</div>
			{/if}
			{#if cve.sources?.length}<div><dt class="inline">Sources:</dt> <dd class="inline">{cve.sources.join(', ')}</dd></div>{/if}
		</dl>
	</section>

	<section class="mt-8">
		<h2 class="h2">Affected products</h2>
		{#if !cve.affects?.length}
			<p class="muted mt-2 text-sm">No affected product data yet.</p>
		{:else}
			<div class="card mt-3 overflow-x-auto">
				<table class="table">
					<thead><tr><th>Product</th><th>Ecosystem</th><th>Affected versions</th><th>Source</th></tr></thead>
					<tbody>
						{#each cve.affects as a, i (i)}
							<tr>
								<td class="font-medium">{productLabel(a.product)}</td>
								<td class="muted text-xs">{a.product.ecosystem}</td>
								<td class="font-mono text-xs">{range(a)}</td>
								<td class="text-xs">
									{a.source}
									{#if !a.confirmed}<Badge tone="unconfirmed" title="Range not confirmed by a second source">unconfirmed</Badge>{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	{#if cve.references?.length}
		<section class="mt-8">
			<h2 class="h2">References</h2>
			<ul class="mt-2 space-y-1 text-sm">
				{#each cve.references as r (r)}
					<li class="truncate">
						{#if /^https?:\/\//i.test(r)}
							<a href={r} class="link" target="_blank" rel="noopener noreferrer nofollow">{r}</a>
						{:else}
							<span class="font-mono text-xs">{r}</span>
						{/if}
						<span class="muted text-xs">{hostOf(r)}</span>
					</li>
				{/each}
			</ul>
		</section>
	{/if}
{/if}
