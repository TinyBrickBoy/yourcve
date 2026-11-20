<script lang="ts">
	import { put, errMsg } from '../api';
	import { fmtCvss, fmtEpss, fmtRelative, truncate } from '../format';
	import { toast } from '../toast.svelte';
	import type { CVEStatus, StackCVE } from '../types';
	import Badge from './Badge.svelte';
	import SeverityBadge from './SeverityBadge.svelte';

	let {
		stackId,
		cves,
		loading,
		includeResolved = $bindable(false),
		onchanged
	}: {
		stackId: number;
		cves: StackCVE[] | null;
		loading: boolean;
		includeResolved?: boolean;
		onchanged: () => void;
	} = $props();

	let filter = $state('');
	let sort = $state<'severity' | 'epss' | 'newest'>('severity');

	const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, none: 1, unknown: 0 };

	const rows = $derived.by(() => {
		const f = filter.trim().toLowerCase();
		let list = (cves ?? []).filter(
			(c) => !f || c.id.toLowerCase().includes(f) || c.description?.toLowerCase().includes(f) || c.reason?.toLowerCase().includes(f)
		);
		list = [...list].sort((a, b) => {
			if (sort === 'epss') return (b.epss ?? -1) - (a.epss ?? -1);
			if (sort === 'newest') return (b.published ?? '').localeCompare(a.published ?? '');
			return (
				Number(b.kev) - Number(a.kev) ||
				(rank[b.severity] ?? 0) - (rank[a.severity] ?? 0) ||
				(b.cvss ?? -1) - (a.cvss ?? -1)
			);
		});
		return list;
	});

	async function setStatus(c: StackCVE, status: CVEStatus) {
		const prev = c.status;
		c.status = status;
		try {
			await put(`/v1/stacks/${stackId}/cves/${encodeURIComponent(c.id)}/status`, { status });
			toast.success(`${c.id} marked as ${status.replace('_', ' ')}`);
			onchanged();
		} catch (e) {
			c.status = prev;
			toast.error(errMsg(e));
		}
	}
</script>

<div class="flex flex-wrap items-center gap-3">
	<input class="input max-w-xs" type="search" placeholder="Filter…" bind:value={filter} />
	<label class="flex items-center gap-2 text-sm">
		<select class="input w-auto py-1" bind:value={sort}>
			<option value="severity">Sort: severity</option>
			<option value="epss">Sort: EPSS</option>
			<option value="newest">Sort: newest</option>
		</select>
	</label>
	<label class="flex items-center gap-2 text-sm">
		<input type="checkbox" bind:checked={includeResolved} /> Include resolved (not affected / patched)
	</label>
	{#if loading}<span class="muted text-xs">refreshing…</span>{/if}
</div>

{#if cves === null}
	<p class="muted mt-6 text-sm">Loading CVEs…</p>
{:else if cves.length === 0}
	<div class="card mt-6 p-6 text-center">
		<p class="font-medium">No {includeResolved ? '' : 'open '}CVEs affect this stack 🎉</p>
		<p class="muted mt-1 text-sm">
			We keep checking. Set up a notification rule to be alerted as soon as a new one appears.
		</p>
	</div>
{:else}
	<div class="card mt-4 overflow-x-auto">
		<table class="table">
			<thead>
				<tr>
					<th>CVE</th>
					<th>Severity</th>
					<th class="text-right">EPSS</th>
					<th>Why it matched</th>
					<th>Status</th>
				</tr>
			</thead>
			<tbody>
				{#each rows as c (c.id)}
					<tr class={c.status !== 'open' ? 'opacity-60' : ''}>
						<td class="min-w-72">
							<div class="flex flex-wrap items-center gap-1.5">
								<a href="/cves/{c.id}" class="link font-mono text-xs font-medium">{c.id}</a>
								{#if c.kev}<Badge tone="kev" title="Known Exploited Vulnerability (CISA KEV)">KEV</Badge>{/if}
								{#if !c.confirmed}<Badge tone="unconfirmed" title="Matched by product name only – version range not confirmed">unconfirmed</Badge>{/if}
								{#if c.category}<Badge tone="ai" title="AI generated category">{c.category}</Badge>{/if}
							</div>
							<p class="muted mt-1 text-xs leading-relaxed">{truncate(c.description, 180)}</p>
						</td>
						<td class="whitespace-nowrap">
							<SeverityBadge severity={c.severity} />
							<div class="muted mt-1 font-mono text-xs">CVSS {fmtCvss(c.cvss)}</div>
						</td>
						<td class="text-right font-mono text-xs whitespace-nowrap">{fmtEpss(c.epss)}</td>
						<td class="text-xs">
							<span class="font-mono">{c.reason}</span>
							<div class="muted mt-0.5">matched {fmtRelative(c.matched_at)}</div>
						</td>
						<td>
							<select
								class="input w-auto py-1 text-xs"
								value={c.status}
								onchange={(e) => setStatus(c, (e.currentTarget as HTMLSelectElement).value as CVEStatus)}
							>
								<option value="open">open</option>
								<option value="not_affected">not affected</option>
								<option value="patched">patched</option>
							</select>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<p class="muted mt-2 text-xs">{rows.length} of {cves.length} shown</p>
{/if}
