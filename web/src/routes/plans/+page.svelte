<script lang="ts">
	import { onMount } from 'svelte';
	import { get, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import type { Plan } from '#lib/types.js';
	import Badge from '#lib/components/Badge.svelte';

	let plans = $state<Plan[] | null>(null);
	let error = $state('');

	onMount(async () => {
		try {
			plans = (await get<Plan[]>('/v1/plans', undefined, { redirectOn401: false })) ?? [];
		} catch (e) {
			error = errMsg(e);
		}
	});

	const current = $derived(session.me?.plan ?? null);
</script>

<svelte:head><title>Plans · yourcve</title></svelte:head>

<h1 class="h1">Plans</h1>
<p class="muted mt-1 text-sm">Start for free. Paid channels (SMS, phone calls, …) will come with Plus.</p>

{#if error}<p class="alert-error mt-4">{error}</p>{/if}

{#if plans === null}
	<p class="muted mt-6 text-sm">Loading…</p>
{:else}
	<div class="mt-6 grid max-w-3xl gap-4 sm:grid-cols-2">
		{#each plans as p (p.id)}
			{@const active = current ? current === p.id : p.id === 'free'}
			<div class="card flex flex-col p-6 {active ? 'ring-2 ring-zinc-900 dark:ring-white' : ''} {p.coming_soon ? 'opacity-80' : ''}">
				<div class="flex items-center justify-between gap-2">
					<h2 class="h2">{p.name}</h2>
					{#if current === p.id}
						<Badge tone="ok">Active</Badge>
					{:else if p.coming_soon}
						<Badge tone="warn">Coming soon</Badge>
					{/if}
				</div>
				<p class="mt-2 text-2xl font-semibold">{p.price || (p.id === 'free' ? '0 €' : '')}</p>
				<ul class="mt-4 flex-1 space-y-1.5 text-sm">
					{#each p.features ?? [] as f (f)}
						<li class="flex gap-2"><span class="text-green-600 dark:text-green-400">✓</span>{f}</li>
					{/each}
				</ul>
				<div class="mt-6">
					{#if p.coming_soon || !p.available}
						<button class="btn w-full" disabled>Coming soon</button>
					{:else if !session.me}
						<a href="/register" class="btn btn-primary w-full">Get started</a>
					{:else if current === p.id}
						<button class="btn w-full" disabled>Your current plan</button>
					{/if}
				</div>
			</div>
		{/each}
	</div>
{/if}
