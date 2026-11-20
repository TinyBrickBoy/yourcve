import type { MatchEvent } from './types';
import { toast } from './toast.svelte';

/** Live match stream (SSE /v1/events) for the logged in user. */
class LiveEvents {
	matches = $state<(MatchEvent & { at: string })[]>([]);
	connected = $state(false);
	private es: EventSource | null = null;
	private listeners = new Set<(m: MatchEvent) => void>();

	start() {
		if (this.es || typeof EventSource === 'undefined') return;
		const es = new EventSource('/v1/events', { withCredentials: true });
		this.es = es;
		es.onopen = () => (this.connected = true);
		es.onerror = () => (this.connected = false);
		es.addEventListener('match', (ev) => {
			let m: MatchEvent;
			try {
				m = JSON.parse((ev as MessageEvent).data);
			} catch {
				return;
			}
			this.matches = [{ ...m, at: new Date().toISOString() }, ...this.matches].slice(0, 20);
			const what =
				m.occasion === 'kev_added'
					? 'is now in the KEV catalog'
					: m.occasion === 'cvss_raised'
						? 'got a higher CVSS score'
						: 'matches one of your stacks';
			toast.info(`${m.cve_id} ${what}`, { href: `/stacks/${m.stack_id}?tab=cves`, linkText: 'Open stack', timeout: 10000 });
			for (const l of this.listeners) l(m);
		});
	}

	stop() {
		this.es?.close();
		this.es = null;
		this.connected = false;
	}

	onMatch(fn: (m: MatchEvent) => void) {
		this.listeners.add(fn);
		return () => this.listeners.delete(fn);
	}
}

export const live = new LiveEvents();
