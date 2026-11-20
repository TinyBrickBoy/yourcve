<script lang="ts">
	import { session } from '#lib/session.svelte.js';
	import Dashboard from './Dashboard.svelte';
</script>

<svelte:head><title>yourcve</title></svelte:head>

{#if session.me}
	<Dashboard />
{:else}
	<section class="mx-auto max-w-3xl py-10 text-center sm:py-16">
		<h1 class="text-4xl font-semibold tracking-tight sm:text-5xl">Know when your stack is vulnerable.</h1>
		<p class="muted mx-auto mt-5 max-w-2xl text-lg">
			Click together the software you run – or drop in a <code class="text-base">package.json</code>, <code
				class="text-base">go.mod</code
			> or SBOM – and get notified on Discord, email or webhook as soon as a matching CVE appears.
		</p>
		<div class="mt-8 flex justify-center gap-3">
			{#if session.config.registration_open}
				<a href="/register" class="btn btn-primary px-5 py-2 text-base">Get started – free</a>
			{/if}
			<a href="/login" class="btn px-5 py-2 text-base">Sign in</a>
		</div>
	</section>

	<section class="mx-auto grid max-w-4xl gap-4 sm:grid-cols-3">
		{#each [
			{ t: '1. Build your stack', d: 'Search products like nginx, OpenSSL or React and pin versions – or import a manifest.' },
			{ t: '2. See your CVEs', d: 'Instantly see every known CVE that affects your versions, with CVSS, EPSS and KEV status.' },
			{ t: '3. Get notified', d: 'New matches go out instantly or as hourly/daily digests – with quiet hours.' }
		] as f (f.t)}
			<div class="card p-5">
				<h3 class="font-medium">{f.t}</h3>
				<p class="muted mt-1.5 text-sm">{f.d}</p>
			</div>
		{/each}
	</section>

	<p class="muted mt-10 text-center text-sm">
		Or just <a href="/cves" class="link">search the CVE database</a> without an account.
	</p>
{/if}
