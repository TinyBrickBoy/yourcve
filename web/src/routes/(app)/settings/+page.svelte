<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { get, post, del, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { copyText, fmtDate, fmtRelative } from '#lib/format.js';
	import { toast } from '#lib/toast.svelte.js';
	import { credentialToJSON, passkeysSupported, toCreationOptions, webauthnError } from '#lib/webauthn.js';
	import type { APIKey, Passkey } from '#lib/types.js';
	import Badge from '#lib/components/Badge.svelte';

	let passkeys = $state<Passkey[] | null>(null);
	let keys = $state<APIKey[] | null>(null);
	let pkName = $state('');
	let pkBusy = $state(false);
	let keyName = $state('');
	let keyBusy = $state(false);
	let newKey = $state<APIKey | null>(null);
	let confirmEmail = $state('');
	let deleting = $state(false);
	const supported = passkeysSupported();
	const origin = typeof location !== 'undefined' ? location.origin : '';
	const baseUrl = $derived((session.config.base_url || origin).replace(/\/$/, ''));

	async function loadPasskeys() {
		try {
			passkeys = (await get<Passkey[]>('/v1/passkeys')) ?? [];
		} catch (e) {
			toast.error(errMsg(e));
		}
	}
	async function loadKeys() {
		try {
			keys = (await get<APIKey[]>('/v1/apikeys')) ?? [];
		} catch (e) {
			toast.error(errMsg(e));
		}
	}
	onMount(() => {
		loadPasskeys();
		loadKeys();
	});

	async function addPasskey(e: SubmitEvent) {
		e.preventDefault();
		pkBusy = true;
		try {
			const opts = await post<unknown>('/v1/auth/passkey/register/begin');
			const cred = (await navigator.credentials.create(toCreationOptions(opts))) as PublicKeyCredential | null;
			if (!cred) return;
			const name = pkName.trim() || defaultPasskeyName();
			await post(`/v1/auth/passkey/register/finish?name=${encodeURIComponent(name)}`, credentialToJSON(cred));
			toast.success('Passkey added');
			pkName = '';
			await loadPasskeys();
		} catch (e) {
			const m = e instanceof DOMException ? webauthnError(e) : errMsg(e);
			if (m) toast.error(m);
		} finally {
			pkBusy = false;
		}
	}

	function defaultPasskeyName() {
		const ua = navigator.userAgent;
		const os = /Mac/.test(ua) ? 'Mac' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Device';
		return `${os} passkey`;
	}

	async function removePasskey(p: Passkey) {
		if (!confirm(`Remove passkey “${p.name}”?`)) return;
		try {
			await del(`/v1/passkeys/${p.id}`);
			await loadPasskeys();
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	async function createKey(e: SubmitEvent) {
		e.preventDefault();
		keyBusy = true;
		try {
			newKey = await post<APIKey>('/v1/apikeys', { name: keyName.trim() });
			keyName = '';
			await loadKeys();
		} catch (e) {
			toast.error(errMsg(e));
		} finally {
			keyBusy = false;
		}
	}

	async function revokeKey(k: APIKey) {
		if (!confirm(`Revoke API key “${k.name}”? Clients using it stop working immediately.`)) return;
		try {
			await del(`/v1/apikeys/${k.id}`);
			if (newKey?.id === k.id) newKey = null;
			await loadKeys();
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	async function copy(text: string) {
		if (await copyText(text)) toast.success('Copied to clipboard');
		else toast.error('Copy failed – please select and copy manually');
	}

	async function deleteAccount(e: SubmitEvent) {
		e.preventDefault();
		if (confirmEmail.trim().toLowerCase() !== session.me?.email.toLowerCase()) return;
		deleting = true;
		try {
			await del('/v1/me');
			session.me = null;
			toast.success('Your account and all data were deleted.');
			await goto('/');
		} catch (e) {
			toast.error(errMsg(e));
		} finally {
			deleting = false;
		}
	}
</script>

<svelte:head><title>Settings · yourcve</title></svelte:head>

<h1 class="h1">Settings</h1>

<div class="mt-6 space-y-8">
	<!-- account -->
	<section class="card p-5">
		<h2 class="h2">Account</h2>
		{#if session.me}
			<dl class="mt-3 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
				<dt class="muted">Email</dt>
				<dd>{session.me.email}</dd>
				<dt class="muted">Plan</dt>
				<dd class="flex items-center gap-2">
					<span class="capitalize">{session.me.plan}</span>
					{#if session.me.role === 'admin'}<Badge tone="info">admin</Badge>{/if}
					<a href="/plans" class="link text-xs">Compare plans</a>
				</dd>
				<dt class="muted">Usage</dt>
				<dd>
					{session.me.usage?.stacks ?? 0} of {session.me.limits?.stacks} stacks · {session.me.usage?.channels ?? 0} of {session.me.limits
						?.channels} channels
				</dd>
				<dt class="muted">Member since</dt>
				<dd>{fmtDate(session.me.created_at)}</dd>
			</dl>
		{/if}
	</section>

	<!-- passkeys -->
	<section class="card p-5">
		<h2 class="h2">Passkeys</h2>
		<p class="muted mt-1 text-sm">Sign in with your fingerprint, face or security key instead of an email link.</p>
		{#if passkeys === null}
			<p class="muted mt-3 text-sm">Loading…</p>
		{:else}
			{#if passkeys.length > 0}
				<ul class="mt-4 divide-y divide-zinc-100 text-sm dark:divide-zinc-800">
					{#each passkeys as p (p.id)}
						<li class="flex items-center justify-between gap-3 py-2">
							<div>
								<span class="font-medium">{p.name || 'Passkey'}</span>
								<span class="muted ml-2 text-xs">added {fmtDate(p.created_at)} · last used {p.last_used_at ? fmtRelative(p.last_used_at) : 'never'}</span>
							</div>
							<button class="btn btn-sm btn-danger" onclick={() => removePasskey(p)}>Remove</button>
						</li>
					{/each}
				</ul>
			{/if}
			{#if supported}
				<form class="mt-4 flex flex-wrap gap-2" onsubmit={addPasskey}>
					<input class="input max-w-xs" bind:value={pkName} placeholder="Name, e.g. MacBook" maxlength="64" />
					<button class="btn btn-primary" disabled={pkBusy}>{pkBusy ? 'Waiting for device…' : 'Add passkey'}</button>
				</form>
			{:else}
				<p class="muted mt-3 text-sm">This browser does not support passkeys.</p>
			{/if}
		{/if}
	</section>

	<!-- api keys -->
	<section class="card p-5">
		<h2 class="h2">API keys</h2>
		<p class="muted mt-1 text-sm">For scripts and AI assistants. Keys have the same read access as your account.</p>

		{#if newKey?.key}
			<div class="alert-ok mt-4">
				<p class="font-medium">New key “{newKey.name}” – copy it now, it will not be shown again.</p>
				<div class="mt-2 flex gap-2">
					<code class="flex-1 overflow-x-auto rounded bg-white px-2 py-1.5 font-mono text-xs whitespace-nowrap text-zinc-900 dark:bg-zinc-900 dark:text-zinc-100">{newKey.key}</code>
					<button class="btn btn-sm" onclick={() => copy(newKey!.key!)}>Copy</button>
				</div>
			</div>
		{/if}

		{#if keys === null}
			<p class="muted mt-3 text-sm">Loading…</p>
		{:else if keys.length > 0}
			<ul class="mt-4 divide-y divide-zinc-100 text-sm dark:divide-zinc-800">
				{#each keys as k (k.id)}
					<li class="flex items-center justify-between gap-3 py-2">
						<div>
							<span class="font-medium">{k.name}</span>
							<code class="muted ml-2 font-mono text-xs">{k.prefix}…</code>
							<span class="muted ml-2 text-xs">created {fmtDate(k.created_at)} · last used {k.last_used_at ? fmtRelative(k.last_used_at) : 'never'}</span>
						</div>
						<button class="btn btn-sm btn-danger" onclick={() => revokeKey(k)}>Revoke</button>
					</li>
				{/each}
			</ul>
		{/if}

		<form class="mt-4 flex flex-wrap gap-2" onsubmit={createKey}>
			<input class="input max-w-xs" bind:value={keyName} placeholder="Name, e.g. Claude Desktop" required maxlength="64" />
			<button class="btn btn-primary" disabled={keyBusy || !keyName.trim()}>Create API key</button>
		</form>

		<details class="mt-5 text-sm">
			<summary class="cursor-pointer font-medium">How to use with MCP / scripts</summary>
			<div class="muted mt-2 space-y-2">
				<p>
					yourcve exposes a read-only MCP server (Streamable HTTP) at <code class="font-mono">POST {baseUrl}/mcp</code>. Send the key as
					<code class="font-mono">Authorization: Bearer &lt;key&gt;</code>.
				</p>
				<pre class="overflow-x-auto rounded-md bg-zinc-100 p-3 font-mono text-xs text-zinc-800 dark:bg-zinc-900 dark:text-zinc-200">{`{
  "mcpServers": {
    "yourcve": {
      "type": "http",
      "url": "${baseUrl}/mcp",
      "headers": { "Authorization": "Bearer <your key>" }
    }
  }
}`}</pre>
				<p>The same key works for the REST API, e.g. <code class="font-mono">curl -H "Authorization: Bearer &lt;key&gt;" {baseUrl}/v1/stacks</code>.</p>
			</div>
		</details>
	</section>

	<!-- delete -->
	<section class="rounded-lg border border-red-200 p-5 dark:border-red-900">
		<h2 class="h2 text-red-700 dark:text-red-400">Delete account</h2>
		<p class="muted mt-1 text-sm">Permanently deletes your account, stacks, channels, rules, passkeys, API keys and delivery log. This cannot be undone.</p>
		<form class="mt-4 flex flex-wrap items-end gap-2" onsubmit={deleteAccount}>
			<div class="min-w-64">
				<label class="label" for="confirm-email">Type your email <strong>{session.me?.email}</strong> to confirm</label>
				<input id="confirm-email" class="input" bind:value={confirmEmail} autocomplete="off" />
			</div>
			<button
				class="btn btn-danger"
				disabled={deleting || confirmEmail.trim().toLowerCase() !== session.me?.email.toLowerCase()}>Delete my account</button
			>
		</form>
	</section>
</div>
