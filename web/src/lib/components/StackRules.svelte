<script lang="ts">
	import { onMount } from 'svelte';
	import { get, post, patch, del, errMsg } from '../api';
	import { toast } from '../toast.svelte';
	import type { Channel, Rule, RuleInput } from '../types';
	import Badge from './Badge.svelte';
	import RuleForm from './RuleForm.svelte';

	let { stackId, oncount = () => {} }: { stackId: number; oncount?: (n: number) => void } = $props();

	let rules = $state<Rule[] | null>(null);
	let channels = $state<Channel[]>([]);
	let editing = $state<number | 'new' | null>(null);
	let busy = $state(false);
	let error = $state('');

	async function load() {
		try {
			const [r, c] = await Promise.all([get<Rule[]>('/v1/rules', { stack_id: stackId }), get<Channel[]>('/v1/channels')]);
			rules = (r ?? []).filter((x) => x.stack_id === stackId);
			channels = c ?? [];
			oncount(rules.length);
		} catch (e) {
			error = errMsg(e);
		}
	}
	onMount(load);

	async function save(input: RuleInput) {
		busy = true;
		try {
			if (editing === 'new') {
				await post<Rule>('/v1/rules', { ...input, stack_id: stackId });
				toast.success('Rule created');
			} else if (typeof editing === 'number') {
				await patch<Rule>(`/v1/rules/${editing}`, input);
				toast.success('Rule saved');
			}
			editing = null;
			await load();
		} catch (e) {
			toast.error(errMsg(e));
		} finally {
			busy = false;
		}
	}

	async function toggle(r: Rule) {
		try {
			await patch(`/v1/rules/${r.id}`, { enabled: !r.enabled });
			r.enabled = !r.enabled;
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	async function remove(r: Rule) {
		if (!confirm(`Delete the rule for “${r.channel_name}”?`)) return;
		try {
			await del(`/v1/rules/${r.id}`);
			await load();
		} catch (e) {
			toast.error(errMsg(e));
		}
	}

	function describe(r: Rule): string {
		const parts: string[] = [];
		parts.push(r.mode === 'instant' ? 'instant' : `${r.mode} digest`);
		if (r.min_cvss > 0) parts.push(`CVSS ≥ ${r.min_cvss}`);
		if (r.min_epss > 0) parts.push(`EPSS ≥ ${Math.round(r.min_epss * 1000) / 10}%`);
		if (r.kev_only) parts.push('KEV only');
		if (!r.include_unconfirmed) parts.push('confirmed only');
		if (r.quiet_start && r.quiet_end) parts.push(`quiet ${r.quiet_start}–${r.quiet_end} ${r.timezone}`);
		return parts.join(' · ');
	}
</script>

{#if error}<p class="alert-error">{error}</p>{/if}

{#if rules === null}
	<p class="muted text-sm">Loading…</p>
{:else if channels.length === 0}
	<div class="card p-6">
		<p class="font-medium">First, add a notification channel</p>
		<p class="muted mt-1 text-sm">Channels are where alerts go: Discord, email, a webhook, … Then come back here and connect it to this stack.</p>
		<a href="/channels" class="btn btn-primary mt-4">Add a channel →</a>
	</div>
{:else}
	{#if rules.length === 0 && editing === null}
		<p class="muted mb-4 text-sm">No rules yet – this stack does not send notifications.</p>
	{/if}

	<ul class="space-y-2">
		{#each rules as r (r.id)}
			<li class="card p-4">
				{#if editing === r.id}
					<RuleForm {channels} initial={r} {busy} onsubmit={save} oncancel={() => (editing = null)} />
				{:else}
					<div class="flex flex-wrap items-center justify-between gap-3">
						<div class="min-w-0">
							<div class="flex items-center gap-2">
								<span class="font-medium">{r.channel_name}</span>
								<Badge>{r.channel_type}</Badge>
								{#if !r.enabled}<Badge tone="warn">paused</Badge>{/if}
							</div>
							<p class="muted mt-1 text-xs">{describe(r)}</p>
						</div>
						<div class="flex gap-2">
							<button class="btn btn-sm" onclick={() => toggle(r)}>{r.enabled ? 'Pause' : 'Resume'}</button>
							<button class="btn btn-sm" onclick={() => (editing = r.id)} disabled={editing !== null}>Edit</button>
							<button class="btn btn-sm btn-danger" onclick={() => remove(r)}>Delete</button>
						</div>
					</div>
				{/if}
			</li>
		{/each}
	</ul>

	{#if editing === 'new'}
		<div class="card mt-3 p-4">
			<h3 class="mb-3 font-medium">New rule</h3>
			<RuleForm {channels} {busy} onsubmit={save} oncancel={() => (editing = null)} />
		</div>
	{:else if editing === null}
		<button class="btn btn-primary mt-3" onclick={() => (editing = 'new')}>+ Add rule</button>
	{/if}
{/if}
