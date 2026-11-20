<script lang="ts">
	import { session } from '#lib/session.svelte.js';
</script>

<svelte:head><title>Unsubscribed · yourcve</title></svelte:head>

<div class="mx-auto max-w-md py-10 text-center">
	<h1 class="h1">You are unsubscribed</h1>
	<p class="muted mt-3 text-sm">
		This email channel has been disabled. You will not receive further alerts at this address.
	</p>
	<p class="mt-6 text-sm">
		{#if session.me}
			<a href="/channels" class="link">Manage your channels</a>
		{:else}
			<a href="/login" class="link">Sign in</a> to manage your channels.
		{/if}
	</p>
</div>
