<script lang="ts">
	import { get, post, errMsg } from '#lib/api.js';
	import { fmtDateTime, fmtRelative } from '#lib/format.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { Delivery, DeliveryStatus } from '#lib/types.js';
	import DeliveryStatusBadge from '#lib/components/DeliveryStatusBadge.svelte';
	import Pager from '#lib/components/Pager.svelte';

	const LIMIT = 50;
	const STATUSES: DeliveryStatus[] = ['pending', 'digest', 'sent', 'failed', 'suppressed'];
	const occasion = { new: 'new match', kev_added: 'added to KEV', cvss_raised: 'CVSS raised' } as const;

	let status = $state<DeliveryStatus | ''>('');
	let offset = $state(0);
	let items = $state<Delivery[] | null>(null);
	let error = $state('');
	let retrying = $state<Record<number, boolean>>({});

	async function load() {
		error = '';
		try {
			items = (await get<Delivery[]>('/v1/deliveries', { status, limit: LIMIT, offset })) ?? [];
		} catch (e) {
			error = errMsg(e);
		}
	}

	$effect(() => {
		void status;
		void offset;
		load();
	});

	async function retry(d: Delivery) {
		retrying[d.id] = true;
		try {
			await post(`/v1/deliveries/${d.id}/retry`);
			toast.success('Delivery queued for retry');
			d.status = 'pending';
			d.last_error = null;
		} catch (e) {
			toast.error(errMsg(e));
		} finally {
			retrying[d.id] = false;
		}
	}
</script>

<svelte:head><title>Deliveries · yourcve</title></svelte:head>

<div class="flex flex-wrap items-end justify-between gap-3">
	<div>
		<h1 class="h1">Deliveries</h1>
		<p class="muted mt-1 text-sm">Every notification yourcve sent (or tried to send), newest first.</p>
	</div>
	<div class="flex items-center gap-2">
		<label class="label mb-0" for="status">Status</label>
		<select id="status" class="input w-auto" bind:value={status} onchange={() => (offset = 0)}>
			<option value="">all</option>
			{#each STATUSES as s (s)}<option value={s}>{s}</option>{/each}
		</select>
		<button class="btn" onclick={load}>Refresh</button>
	</div>
</div>

{#if error}<p class="alert-error mt-4">{error}</p>{/if}

{#if items === null}
	<p class="muted mt-6 text-sm">Loading…</p>
{:else if items.length === 0 && offset === 0}
	<p class="muted mt-6 text-sm">No deliveries{status ? ` with status “${status}”` : ''} yet.</p>
{:else}
	<div class="card mt-6 overflow-x-auto">
		<table class="table">
			<thead>
				<tr><th>CVE</th><th>Stack → Channel</th><th>Occasion</th><th>Status</th><th>Attempts</th><th>Time</th><th></th></tr>
			</thead>
			<tbody>
				{#each items as d (d.id)}
					<tr>
						<td><a href="/cves/{d.cve_id}" class="link font-mono text-xs">{d.cve_id}</a></td>
						<td class="text-xs">
							<a href="/stacks/{d.stack_id}" class="hover:underline">{d.stack_name}</a>
							<span class="muted">→</span>
							{d.channel_name}
						</td>
						<td class="muted text-xs">{occasion[d.occasion] ?? d.occasion}</td>
						<td>
							<DeliveryStatusBadge status={d.status} />
							{#if d.last_error}<p class="mt-1 max-w-xs text-xs break-words text-red-600 dark:text-red-400">{d.last_error}</p>{/if}
							{#if d.next_attempt_at && d.status !== 'sent'}<p class="muted mt-0.5 text-[11px]">next try {fmtRelative(d.next_attempt_at)}</p>{/if}
						</td>
						<td class="text-xs tabular-nums">{d.attempts}</td>
						<td class="muted text-xs whitespace-nowrap" title={fmtDateTime(d.sent_at ?? d.created_at)}>{fmtRelative(d.sent_at ?? d.created_at)}</td>
						<td class="text-right">
							{#if d.status === 'failed'}
								<button class="btn btn-sm" disabled={retrying[d.id]} onclick={() => retry(d)}>Retry</button>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<div class="mt-4">
		<Pager {offset} limit={LIMIT} count={items.length} onchange={(o) => (offset = o)} />
	</div>
{/if}
