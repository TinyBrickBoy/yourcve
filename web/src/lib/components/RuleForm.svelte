<script lang="ts">
	import { untrack } from 'svelte';
	import type { Channel, RuleInput, RuleMode } from '../types';

	let {
		channels,
		initial = undefined,
		busy = false,
		onsubmit,
		oncancel
	}: {
		channels: Channel[];
		initial?: RuleInput;
		busy?: boolean;
		onsubmit: (r: RuleInput) => void;
		oncancel: () => void;
	} = $props();

	const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
	const timezones: string[] = (() => {
		try {
			return Intl.supportedValuesOf('timeZone');
		} catch {
			return ['UTC'];
		}
	})();

	// the form keeps its own copy of the values; props are only read once on creation
	const { initial: init, channels: initialChannels } = untrack(() => ({ initial, channels }));
	let channel_id = $state(init?.channel_id ?? initialChannels.find((c) => c.enabled)?.id ?? initialChannels[0]?.id ?? 0);
	let min_cvss = $state(init?.min_cvss ?? 0);
	let kev_only = $state(init?.kev_only ?? false);
	let min_epss_pct = $state(Math.round((init?.min_epss ?? 0) * 1000) / 10);
	let mode = $state<RuleMode>(init?.mode ?? 'instant');
	let quiet = $state(!!(init?.quiet_start && init?.quiet_end));
	let quiet_start = $state(init?.quiet_start ?? '22:00');
	let quiet_end = $state(init?.quiet_end ?? '07:00');
	let timezone = $state(init?.timezone ?? browserTz);
	let include_unconfirmed = $state(init?.include_unconfirmed ?? true);
	let enabled = $state(init?.enabled ?? true);

	function submit(e: SubmitEvent) {
		e.preventDefault();
		onsubmit({
			channel_id: Number(channel_id),
			min_cvss: Number(min_cvss) || 0,
			kev_only,
			min_epss: Math.min(1, Math.max(0, (Number(min_epss_pct) || 0) / 100)),
			mode,
			quiet_start: quiet ? quiet_start : null,
			quiet_end: quiet ? quiet_end : null,
			timezone: timezone || 'UTC',
			include_unconfirmed,
			enabled
		});
	}
</script>

<form class="grid gap-4 sm:grid-cols-2" onsubmit={submit}>
	<div class="sm:col-span-2">
		<label class="label" for="rf-channel">Send to channel</label>
		<select id="rf-channel" class="input" bind:value={channel_id} required>
			{#each channels as c (c.id)}
				<option value={c.id}>{c.name} ({c.type}){c.verified ? '' : ' – not verified'}{c.enabled ? '' : ' – disabled'}</option>
			{/each}
		</select>
	</div>

	<div>
		<label class="label" for="rf-cvss">Minimum CVSS: <span class="font-mono">{Number(min_cvss).toFixed(1)}</span></label>
		<input id="rf-cvss" type="range" min="0" max="10" step="0.1" bind:value={min_cvss} class="w-full" />
		<div class="muted mt-0.5 flex justify-between text-[11px]"><span>all</span><span>4 medium</span><span>7 high</span><span>9 crit.</span></div>
	</div>
	<div>
		<label class="label" for="rf-epss">Minimum EPSS (exploit probability, %)</label>
		<input id="rf-epss" class="input" type="number" min="0" max="100" step="0.1" bind:value={min_epss_pct} />
	</div>

	<div>
		<span class="label">Delivery</span>
		<div class="flex gap-1">
			{#each [['instant', 'Instant'], ['hourly', 'Hourly digest'], ['daily', 'Daily digest']] as [v, l] (v)}
				<button
					type="button"
					class="btn btn-sm flex-1 {mode === v ? 'btn-primary' : ''}"
					aria-pressed={mode === v}
					onclick={() => (mode = v as RuleMode)}>{l}</button
				>
			{/each}
		</div>
	</div>
	<div class="space-y-1.5 pt-5 text-sm">
		<label class="flex items-center gap-2"><input type="checkbox" bind:checked={kev_only} /> Only known exploited (KEV)</label>
		<label class="flex items-center gap-2"><input type="checkbox" bind:checked={include_unconfirmed} /> Include unconfirmed matches</label>
		<label class="flex items-center gap-2"><input type="checkbox" bind:checked={enabled} /> Rule enabled</label>
	</div>

	<div class="sm:col-span-2">
		<label class="flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={quiet} /> Quiet hours (instant alerts are held back and sent afterwards)</label>
		{#if quiet}
			<div class="mt-2 flex flex-wrap items-end gap-2">
				<div>
					<label class="label" for="rf-qs">From</label>
					<input id="rf-qs" class="input w-28" type="time" bind:value={quiet_start} required />
				</div>
				<div>
					<label class="label" for="rf-qe">Until</label>
					<input id="rf-qe" class="input w-28" type="time" bind:value={quiet_end} required />
				</div>
			</div>
		{/if}
	</div>
	<div class="sm:col-span-2">
		<label class="label" for="rf-tz">Timezone (for quiet hours and daily digests)</label>
		<input id="rf-tz" class="input max-w-xs" list="rf-tz-list" bind:value={timezone} />
		<datalist id="rf-tz-list">
			{#each timezones as tz (tz)}<option value={tz}></option>{/each}
		</datalist>
	</div>

	<div class="flex gap-2 sm:col-span-2">
		<button class="btn btn-primary" disabled={busy || !channel_id}>{initial ? 'Save rule' : 'Create rule'}</button>
		<button type="button" class="btn" onclick={oncancel}>Cancel</button>
	</div>
</form>
