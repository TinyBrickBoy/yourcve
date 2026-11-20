<script lang="ts">
	import { onMount } from 'svelte';
	import { get, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { fmtDuration, fmtNum, fmtRelative, fmtDateTime } from '#lib/format.js';
	import type { AdminStatus } from '#lib/types.js';
	import Badge from '#lib/components/Badge.svelte';

	let data = $state<AdminStatus | null>(null);
	let error = $state('');
	let updated = $state<Date | null>(null);

	async function load() {
		try {
			data = await get<AdminStatus>('/v1/admin/status');
			updated = new Date();
			error = '';
		} catch (e) {
			error = errMsg(e);
		}
	}

	onMount(() => {
		if (session.me?.role !== 'admin') return;
		load();
		const t = setInterval(load, 10_000);
		return () => clearInterval(t);
	});

	const countLabels: Record<string, string> = {
		cves: 'CVEs',
		products: 'Products',
		users: 'Users',
		stacks: 'Stacks',
		ai_summaries: 'AI summaries',
		embeddings: 'Embeddings'
	};

	const lagTone = (s: number | null) => (s == null ? 'muted' : s > 86400 ? 'danger' : s > 6 * 3600 ? 'warn' : 'ok');
</script>

<svelte:head><title>Admin · yourcve</title></svelte:head>

{#if session.me?.role !== 'admin'}
	<p class="alert-error">This page is only available to administrators.</p>
{:else}
	<div class="flex items-end justify-between gap-3">
		<h1 class="h1">Admin</h1>
		<span class="muted text-xs">auto refresh every 10s{updated ? ` · updated ${updated.toLocaleTimeString()}` : ''}</span>
	</div>

	{#if error}<p class="alert-error mt-4">{error}</p>{/if}

	{#if !data}
		<p class="muted mt-6 text-sm">Loading…</p>
	{:else}
		<div class="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
			{#each Object.entries(data.counts ?? {}) as [k, v] (k)}
				<div class="card p-3">
					<div class="muted text-xs">{countLabels[k] ?? k}</div>
					<div class="mt-1 text-xl font-semibold tabular-nums">{fmtNum(v)}</div>
				</div>
			{/each}
		</div>

		<section class="mt-8">
			<h2 class="h2">Sources</h2>
			<div class="card mt-3 overflow-x-auto">
				<table class="table">
					<thead>
						<tr><th>Source</th><th>Last run</th><th>Last success</th><th>Lag</th><th class="text-right">Items</th><th>Cursor</th><th>Last error</th></tr>
					</thead>
					<tbody>
						{#each data.sources ?? [] as s (s.source)}
							<tr>
								<td class="font-medium">{s.source}</td>
								<td class="text-xs" title={fmtDateTime(s.last_run)}>{fmtRelative(s.last_run)}</td>
								<td class="text-xs" title={fmtDateTime(s.last_success)}>{fmtRelative(s.last_success)}</td>
								<td><Badge tone={lagTone(s.lag_seconds)}>{fmtDuration(s.lag_seconds)}</Badge></td>
								<td class="text-right tabular-nums">{fmtNum(s.items_total)}</td>
								<td class="muted max-w-40 truncate font-mono text-xs" title={s.cursor}>{s.cursor || '–'}</td>
								<td class="max-w-xs text-xs break-words text-red-600 dark:text-red-400">{s.last_error ?? ''}</td>
							</tr>
						{:else}
							<tr><td colspan="7" class="muted">No sources reported.</td></tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		<div class="mt-8 grid gap-6 md:grid-cols-2">
			<section>
				<h2 class="h2">Job queue</h2>
				<dl class="mt-3 grid grid-cols-4 gap-3">
					{#each Object.entries(data.queue ?? {}) as [k, v] (k)}
						<div class="card p-3"><dt class="muted text-xs capitalize">{k}</dt><dd class="mt-1 text-lg font-semibold tabular-nums">{fmtNum(v)}</dd></div>
					{/each}
				</dl>
			</section>
			<section>
				<h2 class="h2">Deliveries</h2>
				<dl class="mt-3 grid grid-cols-3 gap-3">
					<div class="card p-3"><dt class="muted text-xs">Pending</dt><dd class="mt-1 text-lg font-semibold tabular-nums">{fmtNum(data.deliveries?.pending)}</dd></div>
					<div class="card p-3"><dt class="muted text-xs">Sent (24h)</dt><dd class="mt-1 text-lg font-semibold tabular-nums">{fmtNum(data.deliveries?.sent_24h)}</dd></div>
					<div class="card p-3">
						<dt class="muted text-xs">Failed (24h)</dt>
						<dd class="mt-1 text-lg font-semibold tabular-nums {data.deliveries?.failed_24h ? 'text-red-600 dark:text-red-400' : ''}">{fmtNum(data.deliveries?.failed_24h)}</dd>
					</div>
				</dl>
			</section>
		</div>

		<section class="mt-8">
			<h2 class="h2">Recent failures</h2>
			{#if !data.recent_failures?.length}
				<p class="muted mt-2 text-sm">None.</p>
			{:else}
				<div class="card mt-3 overflow-x-auto">
					<table class="table">
						<thead><tr><th>Time</th><th>CVE</th><th>Stack → Channel</th><th>Attempts</th><th>Error</th></tr></thead>
						<tbody>
							{#each data.recent_failures as d (d.id)}
								<tr>
									<td class="text-xs whitespace-nowrap">{fmtRelative(d.created_at)}</td>
									<td><a href="/cves/{d.cve_id}" class="link font-mono text-xs">{d.cve_id}</a></td>
									<td class="text-xs">{d.stack_name} → {d.channel_name}</td>
									<td class="text-xs tabular-nums">{d.attempts}</td>
									<td class="text-xs break-words text-red-600 dark:text-red-400">{d.last_error}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
	{/if}
{/if}
