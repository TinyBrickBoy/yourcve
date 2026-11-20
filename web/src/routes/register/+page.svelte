<script lang="ts">
	import { page } from '$app/state';
	import { session } from '#lib/session.svelte.js';
	import EmailAltchaForm from '#lib/components/EmailAltchaForm.svelte';
</script>

<svelte:head><title>Register · yourcve</title></svelte:head>

<div class="mx-auto max-w-sm py-6">
	<h1 class="h1">Create your account</h1>
	<p class="muted mt-1 text-sm">No password needed – we email you a sign-in link.</p>

	{#if page.url.searchParams.get('error') === 'invalid_link'}
		<p class="alert-error mt-4">That link is invalid or has expired. Please request a new one.</p>
	{/if}

	<div class="mt-6">
		{#if session.me}
			<p class="alert-info">You are already signed in. <a href="/" class="link">Go to the dashboard</a></p>
		{:else if !session.config.registration_open}
			<p class="alert-info">Registration is currently closed on this instance.</p>
		{:else}
			<EmailAltchaForm endpoint="/v1/auth/register" submitLabel="Send sign-up link" />
		{/if}
	</div>

	<p class="muted mt-6 text-sm">Already have an account? <a href="/login" class="link">Sign in</a></p>
	<p class="muted mt-2 text-xs">
		By registering you accept our <a href="/privacy" class="link">privacy policy</a>.
	</p>
</div>
