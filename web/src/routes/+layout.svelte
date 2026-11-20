<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { session } from '#lib/session.svelte.js';
	import { live } from '#lib/events.svelte.js';
	import Toasts from '#lib/components/Toasts.svelte';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
	let menuOpen = $state(false);

	onMount(() => {
		session.load();
		return () => live.stop();
	});

	$effect(() => {
		if (session.me) live.start();
		else live.stop();
	});

	const nav = $derived(
		session.me
			? [
					{ href: '/', label: 'Dashboard' },
					{ href: '/stacks', label: 'Stacks' },
					{ href: '/cves', label: 'CVEs' },
					{ href: '/channels', label: 'Channels' },
					{ href: '/deliveries', label: 'Deliveries' },
					{ href: '/settings', label: 'Settings' },
					...(session.me.role === 'admin' ? [{ href: '/admin', label: 'Admin' }] : [])
				]
			: [
					{ href: '/cves', label: 'CVEs' },
					{ href: '/plans', label: 'Plans' }
				]
	);

	function isActive(href: string) {
		const p = page.url.pathname;
		return href === '/' ? p === '/' : p === href || p.startsWith(href + '/');
	}

	async function logout() {
		try {
			await fetch('/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
		} catch {
			/* ignore */
		}
		session.me = null;
		menuOpen = false;
		await goto('/');
	}

	$effect(() => {
		// close the mobile menu on navigation
		void page.url.pathname;
		menuOpen = false;
	});
</script>

<div class="flex min-h-screen flex-col">
	<header class="sticky top-0 z-30 border-b border-zinc-200 bg-white/85 backdrop-blur dark:border-zinc-800 dark:bg-zinc-950/85">
		<div class="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4">
			<a href="/" class="flex items-center gap-2 font-semibold tracking-tight">
				<img src="/favicon.svg" alt="" class="h-6 w-6" />
				yourcve
			</a>
			{#if session.loaded}
				<nav class="hidden flex-1 items-center gap-1 md:flex">
					{#each nav as item (item.href)}
						<a
							href={item.href}
							class="rounded-md px-2.5 py-1.5 text-sm {isActive(item.href)
								? 'bg-zinc-100 font-medium text-zinc-900 dark:bg-zinc-800 dark:text-white'
								: 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'}">{item.label}</a
						>
					{/each}
				</nav>
				<div class="ml-auto hidden items-center gap-2 md:flex">
					{#if session.me}
						{#if live.connected}
							<span class="muted flex items-center gap-1.5 text-xs" title="Receiving live matches">
								<span class="h-1.5 w-1.5 rounded-full bg-green-500"></span> live
							</span>
						{/if}
						<button class="btn btn-ghost btn-sm" onclick={logout}>Logout</button>
					{:else}
						<a href="/login" class="btn btn-ghost btn-sm">Sign in</a>
						<a href="/register" class="btn btn-primary btn-sm">Register</a>
					{/if}
				</div>
				<button class="btn btn-ghost btn-sm ml-auto md:hidden" aria-label="Menu" onclick={() => (menuOpen = !menuOpen)}>
					<svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M3 5h14v2H3zm0 4h14v2H3zm0 4h14v2H3z" /></svg>
				</button>
			{/if}
		</div>
		{#if menuOpen}
			<nav class="border-t border-zinc-200 px-4 py-2 md:hidden dark:border-zinc-800">
				{#each nav as item (item.href)}
					<a href={item.href} class="block rounded px-2 py-2 text-sm {isActive(item.href) ? 'font-medium' : 'muted'}">{item.label}</a>
				{/each}
				{#if session.me}
					<button class="block w-full px-2 py-2 text-left text-sm" onclick={logout}>Logout</button>
				{:else}
					<a href="/login" class="block px-2 py-2 text-sm">Sign in</a>
					<a href="/register" class="block px-2 py-2 text-sm">Register</a>
				{/if}
			</nav>
		{/if}
	</header>

	<main class="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
		{#if session.loaded}
			{@render children()}
		{:else}
			<p class="muted text-sm">Loading…</p>
		{/if}
	</main>

	<footer class="border-t border-zinc-200 dark:border-zinc-800">
		<div class="muted mx-auto flex max-w-6xl flex-wrap items-center gap-x-5 gap-y-1 px-4 py-5 text-xs">
			<span>yourcve – CVE alerts for your stack</span>
			<a href="/privacy" class="hover:underline">Privacy</a>
			<a href="/imprint" class="hover:underline">Imprint</a>
			<a href="/plans" class="hover:underline">Plans</a>
		</div>
	</footer>
</div>

<Toasts />
