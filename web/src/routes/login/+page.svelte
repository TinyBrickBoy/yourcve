<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { post, errMsg } from '#lib/api.js';
	import { session } from '#lib/session.svelte.js';
	import { credentialToJSON, passkeysSupported, toRequestOptions, webauthnError } from '#lib/webauthn.js';
	import EmailAltchaForm from '#lib/components/EmailAltchaForm.svelte';
	import type { Me } from '#lib/types.js';

	let pkBusy = $state(false);
	let pkError = $state('');
	const supported = passkeysSupported();

	async function passkeyLogin() {
		pkBusy = true;
		pkError = '';
		try {
			const opts = await post<unknown>('/v1/auth/passkey/login/begin', undefined, { redirectOn401: false });
			const cred = (await navigator.credentials.get(toRequestOptions(opts))) as PublicKeyCredential | null;
			if (!cred) return;
			const me = await post<Me>('/v1/auth/passkey/login/finish', credentialToJSON(cred), { redirectOn401: false });
			if (me && typeof me === 'object' && 'email' in me) session.me = me;
			else await session.refreshMe();
			await goto('/');
		} catch (e) {
			const m = e instanceof DOMException ? webauthnError(e) : errMsg(e);
			if (m) pkError = m;
		} finally {
			pkBusy = false;
		}
	}
</script>

<svelte:head><title>Sign in · yourcve</title></svelte:head>

<div class="mx-auto max-w-sm py-6">
	<h1 class="h1">Sign in</h1>
	<p class="muted mt-1 text-sm">We email you a one-time sign-in link.</p>

	{#if page.url.searchParams.get('error') === 'invalid_link'}
		<p class="alert-error mt-4">That sign-in link is invalid or has expired. Please request a new one.</p>
	{/if}

	{#if session.me}
		<p class="alert-info mt-6">You are already signed in. <a href="/" class="link">Go to the dashboard</a></p>
	{:else}
		<div class="mt-6">
			<EmailAltchaForm endpoint="/v1/auth/magic-link" submitLabel="Email me a sign-in link" />
		</div>

		{#if supported}
			<div class="muted my-6 flex items-center gap-3 text-xs">
				<span class="h-px flex-1 bg-zinc-200 dark:bg-zinc-800"></span>or<span class="h-px flex-1 bg-zinc-200 dark:bg-zinc-800"></span>
			</div>
			<button class="btn w-full py-2" onclick={passkeyLogin} disabled={pkBusy}>
				<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="4" /><path d="M2 20c0-3.3 2.7-6 6-6 1.4 0 2.6.5 3.6 1.2M15 11a3 3 0 1 1 3 3v6l-1.5 1.5L15 20l1-1-1-1 1-1" /></svg>
				{pkBusy ? 'Waiting for passkey…' : 'Sign in with passkey'}
			</button>
			{#if pkError}<p class="alert-error mt-3">{pkError}</p>{/if}
		{/if}
	{/if}

	{#if session.config.registration_open}
		<p class="muted mt-6 text-sm">New here? <a href="/register" class="link">Create an account</a></p>
	{/if}
</div>
