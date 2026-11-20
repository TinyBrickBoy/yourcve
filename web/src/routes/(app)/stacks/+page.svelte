<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { get, post, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { fmtDate } from '#lib/format.js';
	import type { Stack } from '#lib/types.js';

	let stacks = $state<Stack[] | null>(null);
	let name = $state('');
	let busy = $state(false);
	let error = $state('');

	const limit = $derived(session.me?.limits?.stacks ?? session.config.free_limits.stacks);
	const used = $derived(stacks?.length ?? session.me?.usage?.stacks ?? 0);
	const full = $derived(limit > 0 && used >= limit);

	onMount(async () => {
		try {
			stacks = (await get<Stack[]>('/v1/stacks')) ?? [];
		} catch (e) {
			error = errMsg(e);
		}
	});

	async function create(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = '';
		try {
			const s = await post<Stack>('/v1/stacks', { name: name.trim() });
			session.refreshMe();
			await goto(`/stacks/${s.id}`);
		} catch (e) {
			error = errMsg(e);
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>Stacks · yourcve</title></svelte:head>

<div class="flex flex-wrap items-end justify-between gap-3">
	<div>
		<h1 class="h1">Stacks</h1>
		<p class="muted mt-1 text-sm">{used} of {limit} used</p>
	</div>
</div>

<form class="card mt-6 flex flex-wrap items-end gap-2 p-4" onsubmit={create}>
	<div class="min-w-56 flex-1">
		<label class="label" for="stack-name">New stack</label>
		<input id="stack-name" class="input" bind:value={name} placeholder="e.g. Production web server" maxlength="100" required disabled={full} />
	</div>
	<button class="btn btn-primary" disabled={busy || full || !name.trim()}>Create stack →</button>
	{#if full}
		<p class="muted w-full text-xs">
			You reached the limit of {limit} stacks on the {session.me?.plan ?? 'free'} plan. Delete a stack or see <a href="/plans" class="link">plans</a>.
		</p>
	{/if}
</form>

{#if error}<p class="alert-error mt-4">{error}</p>{/if}

{#if stacks === null}
	<p class="muted mt-6 text-sm">Loading…</p>
{:else if stacks.length === 0}
	<p class="muted mt-6 text-sm">No stacks yet. Create one above – it takes a few seconds.</p>
{:else}
	<div class="card mt-6 overflow-x-auto">
		<table class="table">
			<thead>
				<tr><th>Name</th><th class="text-right">Products</th><th class="text-right">Open CVEs</th><th class="text-right">Critical</th><th>Created</th></tr>
			</thead>
			<tbody>
				{#each stacks as s (s.id)}
					<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-900">
						<td><a href="/stacks/{s.id}" class="font-medium hover:underline">{s.name}</a></td>
						<td class="text-right tabular-nums">{s.item_count}</td>
						<td class="text-right tabular-nums">{s.open_cves}</td>
						<td class="text-right tabular-nums {s.critical_cves > 0 ? 'font-semibold text-red-600 dark:text-red-400' : ''}">{s.critical_cves}</td>
						<td class="muted">{fmtDate(s.created_at)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
