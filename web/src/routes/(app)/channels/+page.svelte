<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { get, post, del, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { fmtDate } from '#lib/format.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { Channel, ChannelType, Plan } from '#lib/types.js';
	import Badge from '#lib/components/Badge.svelte';

	let types = $state<ChannelType[]>([]);
	let channels = $state<Channel[] | null>(null);
	let plusPrice = $state('9.99 €/month');
	let error = $state('');

	let selected = $state<ChannelType | null>(null);
	let name = $state('');
	let config = $state<Record<string, string>>({});
	let creating = $state(false);
	let createError = $state('');
	let emailHint = $state('');
	let testing = $state<Record<number, boolean>>({});

	const limit = $derived(session.me?.limits?.channels ?? session.config.free_limits.channels);
	const used = $derived(channels?.length ?? session.me?.usage?.channels ?? 0);
	const full = $derived(limit > 0 && used >= limit);
	const typeLabel = (t: string) => types.find((x) => x.type === t)?.label ?? t;

	async function load() {
		try {
			const [t, c] = await Promise.all([get<ChannelType[]>('/v1/channel-types'), get<Channel[]>('/v1/channels')]);
			types = t ?? [];
			channels = c ?? [];
		} catch (e) {
			error = errMsg(e);
		}
	}

	onMount(() => {
		load();
		get<Plan[]>('/v1/plans')
			.then((p) => {
				const plus = p?.find((x) => x.id === 'plus');
				if (plus?.price) plusPrice = plus.price;
			})
			.catch(() => {});
		if (page.url.searchParams.get('confirmed') === '1') {
			toast.success('Email address confirmed – the channel is ready.');
			goto('/channels', { replace: true, reset: false });
		}
	});

	function choose(t: ChannelType) {
		if (!t.available || t.class === 'paid') return;
		selected = t;
		name = name || t.label;
		config = Object.fromEntries((t.fields ?? []).map((f) => [f.key, '']));
		createError = '';
	}

	async function create(e: SubmitEvent) {
		e.preventDefault();
		if (!selected) return;
		creating = true;
		createError = '';
		try {
			const cfg = Object.fromEntries(Object.entries(config).filter(([, v]) => v.trim() !== '').map(([k, v]) => [k, v.trim()]));
			const ch = await post<Channel>('/v1/channels', { type: selected.type, name: name.trim(), config: cfg });
			if (selected.type === 'email') {
				emailHint = `We sent a confirmation link to ${cfg.address ?? cfg.email ?? cfg.to ?? Object.values(cfg)[0] ?? 'the address'}. Click it to activate the channel.`;
			} else {
				toast.success('Channel created – send a test message to verify it.');
			}
			selected = null;
			name = '';
			config = {};
			session.refreshMe();
			await load();
			if (ch && ch.type !== 'email') test(ch);
		} catch (e) {
			createError = (e as { status?: number }).status === 402 ? `This channel type needs the Plus plan (coming soon).` : errMsg(e);
		} finally {
			creating = false;
		}
	}

	async function test(c: Channel) {
		testing[c.id] = true;
		try {
			await post(`/v1/channels/${c.id}/test`);
			toast.success(`Test message sent to “${c.name}”.`);
			await load();
		} catch (e) {
			toast.error(`Test failed: ${errMsg(e)}`);
		} finally {
			testing[c.id] = false;
		}
	}

	async function remove(c: Channel) {
		if (!confirm(`Delete channel “${c.name}”? Rules that use it are removed too.`)) return;
		try {
			await del(`/v1/channels/${c.id}`);
			session.refreshMe();
			await load();
		} catch (e) {
			toast.error(errMsg(e));
		}
	}
</script>

<svelte:head><title>Channels · yourcve</title></svelte:head>

<h1 class="h1">Channels</h1>
<p class="muted mt-1 text-sm">Where your alerts go. {used} of {limit} used.</p>

{#if error}<p class="alert-error mt-4">{error}</p>{/if}
{#if emailHint}
	<div class="alert-info mt-4 flex items-start justify-between gap-3">
		<span><strong>Confirmation sent.</strong> {emailHint}</span>
		<button class="muted" aria-label="Dismiss" onclick={() => (emailHint = '')}>×</button>
	</div>
{/if}

{#if channels === null}
	<p class="muted mt-6 text-sm">Loading…</p>
{:else}
	{#if channels.length > 0}
		<ul class="mt-6 space-y-2">
			{#each channels as c (c.id)}
				<li class="card flex flex-wrap items-center justify-between gap-3 p-4">
					<div class="min-w-0">
						<div class="flex flex-wrap items-center gap-2">
							<span class="font-medium">{c.name}</span>
							<Badge>{typeLabel(c.type)}</Badge>
							{#if c.verified}
								<Badge tone="ok">verified</Badge>
							{:else if c.type === 'email'}
								<Badge tone="warn" title="Click the link in the confirmation email">confirmation pending</Badge>
							{:else}
								<Badge tone="warn" title="Send a test message to verify">not verified</Badge>
							{/if}
							{#if !c.enabled}<Badge tone="danger">disabled</Badge>{/if}
						</div>
						<p class="muted mt-1 truncate font-mono text-xs">
							{Object.entries(c.config ?? {})
								.map(([k, v]) => `${k}: ${v}`)
								.join(' · ')}
						</p>
						<p class="muted mt-0.5 text-xs">Added {fmtDate(c.created_at)}</p>
					</div>
					<div class="flex gap-2">
						<button class="btn btn-sm" onclick={() => test(c)} disabled={testing[c.id]}>{testing[c.id] ? 'Sending…' : 'Send test'}</button>
						<button class="btn btn-sm btn-danger" onclick={() => remove(c)}>Delete</button>
					</div>
				</li>
			{/each}
		</ul>
	{/if}

	<section class="card mt-8 p-5">
		<h2 class="h2">Add a channel</h2>
		{#if full}
			<p class="muted mt-2 text-sm">You reached the limit of {limit} channels. Delete one to add another.</p>
		{:else}
			<div class="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
				{#each types as t (t.type)}
					{@const paid = t.class === 'paid' || !t.available}
					<button
						type="button"
						class="rounded-lg border px-3 py-2.5 text-left text-sm transition {selected?.type === t.type
							? 'border-zinc-900 ring-1 ring-zinc-900 dark:border-white dark:ring-white'
							: 'border-zinc-200 dark:border-zinc-800'} {paid
							? 'cursor-not-allowed opacity-50'
							: 'hover:border-zinc-400 dark:hover:border-zinc-600'}"
						disabled={paid}
						title={paid ? `Coming soon: Plus for ${plusPrice}` : ''}
						onclick={() => choose(t)}
					>
						<span class="font-medium">{t.label}</span>
						{#if paid}<span class="muted mt-0.5 block text-[11px]">Coming soon: Plus for {plusPrice}</span>{/if}
					</button>
				{/each}
			</div>

			{#if selected}
				<form class="mt-5 max-w-lg space-y-4" onsubmit={create}>
					<div>
						<label class="label" for="ch-name">Name</label>
						<input id="ch-name" class="input" bind:value={name} required maxlength="100" />
					</div>
					{#each selected.fields ?? [] as f (f.key)}
						<div>
							<label class="label" for="ch-{f.key}">{f.label}{f.required ? '' : ' (optional)'}</label>
							<input
								id="ch-{f.key}"
								class="input font-mono"
								type={f.secret ? 'password' : f.key.includes('email') || f.key === 'address' ? 'email' : 'text'}
								autocomplete="off"
								placeholder={f.placeholder ?? ''}
								required={f.required}
								bind:value={config[f.key]}
							/>
							{#if f.help}<p class="muted mt-1 text-xs">{f.help}</p>{/if}
						</div>
					{/each}
					{#if selected.type === 'email'}
						<p class="muted text-xs">We will send a confirmation link to this address before any alert is delivered.</p>
					{:else}
						<p class="muted text-xs">After saving we send a test message to verify the channel.</p>
					{/if}
					{#if createError}<p class="alert-error">{createError}</p>{/if}
					<div class="flex gap-2">
						<button class="btn btn-primary" disabled={creating}>{creating ? 'Saving…' : 'Save channel'}</button>
						<button type="button" class="btn" onclick={() => (selected = null)}>Cancel</button>
					</div>
				</form>
			{/if}
		{/if}
	</section>
{/if}
