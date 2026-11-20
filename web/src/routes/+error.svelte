<script lang="ts">
	import { page } from '$app/state';
</script>

<svelte:head><title>{page.status} · yourcve</title></svelte:head>

<div class="mx-auto max-w-md py-16 text-center">
	<h1 class="h1">{page.status === 404 ? 'Page not found' : 'Something went wrong'}</h1>
	<p class="muted mt-2 text-sm">{page.error?.message}</p>
	<a href="/" class="btn mt-6">Back home</a>
</div>
