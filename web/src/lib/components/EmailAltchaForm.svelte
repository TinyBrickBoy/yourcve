<script lang="ts">
	import { post, errMsg } from '../api';
	import Altcha from './Altcha.svelte';

	let { endpoint, submitLabel }: { endpoint: string; submitLabel: string } = $props();

	let email = $state('');
	let altcha = $state('');
	let busy = $state(false);
	let error = $state('');
	let sentTo = $state('');
	let widget: Altcha | undefined = $state();

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		if (!altcha) {
			error = 'Please complete the “I’m not a robot” check first.';
			return;
		}
		busy = true;
		try {
			await post(endpoint, { email: email.trim(), altcha }, { redirectOn401: false });
			sentTo = email.trim();
		} catch (e) {
			error = errMsg(e);
			widget?.reset();
		} finally {
			busy = false;
		}
	}
</script>

{#if sentTo}
	<div class="alert-ok">
		<p class="font-medium">Check your inbox</p>
		<p class="mt-1">
			If <strong>{sentTo}</strong> can sign in, we just sent a link to it. Click the link in the email to continue – it is valid for a
			limited time.
		</p>
	</div>
	<button class="link mt-4 text-sm" onclick={() => ((sentTo = ''), (altcha = ''))}>Use a different address</button>
{:else}
	<form class="space-y-4" onsubmit={submit}>
		<div>
			<label class="label" for="email">Email</label>
			<!-- svelte-ignore a11y_autofocus -->
			<input id="email" class="input" type="email" autocomplete="email" required bind:value={email} autofocus />
		</div>
		<Altcha bind:this={widget} bind:payload={altcha} />
		{#if error}<p class="alert-error">{error}</p>{/if}
		<button class="btn btn-primary w-full py-2" disabled={busy || !email}>{busy ? 'Sending…' : submitLabel}</button>
	</form>
{/if}
