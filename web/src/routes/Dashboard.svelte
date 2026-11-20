<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { get, post, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { live } from '#lib/events.svelte.js';
	import { fmtRelative } from '#lib/format.js';
	import type { Delivery, Stack } from '#lib/types.js';
	import DeliveryStatusBadge from '#lib/components/DeliveryStatusBadge.svelte';

	let stacks = $state<Stack[] | null>(null);
	let deliveries = $state<Delivery[]>([]);
	let error = $state('');
	let newName = $state('');
	let creating = $state(false);

	const stackName = (id: number) => stacks?.find((s) => s.id === id)?.name ?? `Stack #${id}`;
	const totals = $derived({
		open: stacks?.reduce((a, s) => a + (s.open_cves ?? 0), 0) ?? 0,
		critical: stacks?.reduce((a, s) => a + (s.critical_cves ?? 0), 0) ?? 0
	});

	async function load() {
		try {
			const [s, d] = await Promise.all([
				get<Stack[]>('/v1/stacks'),
				get<Delivery[]>('/v1/deliveries', { limit: 8 }).catch(() => [] as Delivery[])
			]);
			stacks = s ?? [];
			deliveries = d ?? [];
		} catch (e) {
			error = errMsg(e);
		}
	}

	async function createStack(e: SubmitEvent) {
		e.preventDefault();
		if (!newName.trim()) return;
		creating = true;
		error = '';
		try {
			const s = await post<Stack>('/v1/stacks', { name: newName.trim() });
			session.refreshMe();
			await goto(`/stacks/${s.id}`);
		} catch (e) {
			error = errMsg(e);
		} finally {
			creating = false;
		}
	}

	onMount(() => {
		load();
		return live.onMatch(() => load());
	});
</script>

<div class="flex flex-wrap items-end justify-between gap-4">
	<div>
		<h1 class="h1">Dashboard</h1>
		<p class="muted mt-1 text-sm">Signed in as {session.me?.email}</p>
	</div>
	{#if stacks && stacks.length > 0}
		<div class="flex gap-6 text-right">
			<div>
				<div class="text-2xl font-semibold tabular-nums">{totals.open}</div>
				<div class="muted text-xs">open CVEs</div>
			</div>
			<div>
				<div class="text-2xl font-semibold text-red-600 tabular-nums dark:text-red-400">{totals.critical}</div>
				<div class="muted text-xs">critical</div>
			</div>
		</div>
	{/if}
</div>

{#if error}<p class="alert-error mt-4">{error}</p>{/if}

{#if stacks === null}
	<p class="muted mt-8 text-sm">Loading…</p>
{:else if stacks.length === 0}
	<div class="card mt-8 p-8">
		<h2 class="h2">Create your first stack</h2>
		<p class="muted mt-1 max-w-xl text-sm">
			A stack is a list of software you run, e.g. “Production web server”. Give it a name – next you add products and
			immediately see which CVEs affect them.
		</p>
		<form class="mt-5 flex max-w-lg gap-2" onsubmit={createStack}>
			<!-- svelte-ignore a11y_autofocus -->
			<input class="input" bind:value={newName} placeholder="e.g. Production web server" autofocus required maxlength="100" />
			<button class="btn btn-primary shrink-0" disabled={creating || !newName.trim()}>Create stack →</button>
		</form>
	</div>
{:else}
	<div class="mt-8 grid gap-8 lg:grid-cols-3">
		<section class="lg:col-span-2">
			<div class="mb-3 flex items-center justify-between">
				<h2 class="h2">Your stacks</h2>
				<a href="/stacks" class="link text-sm">Manage →</a>
			</div>
			<div class="grid gap-3 sm:grid-cols-2">
				{#each stacks as s (s.id)}
					<a href="/stacks/{s.id}" class="card block p-4 transition hover:border-zinc-400 dark:hover:border-zinc-600">
						<div class="flex items-start justify-between gap-2">
							<h3 class="truncate font-medium">{s.name}</h3>
							<span class="muted shrink-0 text-xs">{s.item_count} product{s.item_count === 1 ? '' : 's'}</span>
						</div>
						<div class="mt-3 flex items-baseline gap-4 text-sm">
							<span><span class="text-lg font-semibold tabular-nums">{s.open_cves}</span> <span class="muted">open</span></span>
							<span class={s.critical_cves > 0 ? 'text-red-600 dark:text-red-400' : 'muted'}>
								<span class="text-lg font-semibold tabular-nums">{s.critical_cves}</span> critical
							</span>
						</div>
						{#if s.item_count === 0}
							<p class="mt-2 text-xs text-amber-700 dark:text-amber-400">No products yet – add some →</p>
						{/if}
					</a>
				{/each}
			</div>
		</section>

		<aside class="space-y-8">
			<section>
				<h2 class="h2 mb-3 flex items-center gap-2">
					Live matches
					{#if live.connected}<span class="h-2 w-2 rounded-full bg-green-500" title="connected"></span>{/if}
				</h2>
				{#if live.matches.length === 0}
					<p class="muted text-sm">New matching CVEs will pop up here while this page is open.</p>
				{:else}
					<ul class="space-y-2 text-sm">
						{#each live.matches as m (m.at + m.cve_id + m.stack_id)}
							<li class="card flex items-center justify-between gap-2 px-3 py-2">
								<a href="/cves/{m.cve_id}" class="link font-mono text-xs">{m.cve_id}</a>
								<a href="/stacks/{m.stack_id}?tab=cves" class="muted truncate text-xs hover:underline">{stackName(m.stack_id)}</a>
							</li>
						{/each}
					</ul>
				{/if}
			</section>

			<section>
				<div class="mb-3 flex items-center justify-between">
					<h2 class="h2">Recent deliveries</h2>
					<a href="/deliveries" class="link text-sm">All →</a>
				</div>
				{#if deliveries.length === 0}
					<p class="muted text-sm">
						No notifications sent yet.
						<a href="/channels" class="link">Add a channel</a> and a rule on a stack to get alerts.
					</p>
				{:else}
					<ul class="divide-y divide-zinc-100 text-sm dark:divide-zinc-800">
						{#each deliveries as d (d.id)}
							<li class="flex items-center justify-between gap-2 py-2">
								<div class="min-w-0">
									<a href="/cves/{d.cve_id}" class="link font-mono text-xs">{d.cve_id}</a>
									<div class="muted truncate text-xs">{d.stack_name} → {d.channel_name}</div>
								</div>
								<div class="shrink-0 text-right">
									<DeliveryStatusBadge status={d.status} />
									<div class="muted mt-0.5 text-[11px]">{fmtRelative(d.sent_at ?? d.created_at)}</div>
								</div>
							</li>
						{/each}
					</ul>
				{/if}
			</section>
		</aside>
	</div>
{/if}
