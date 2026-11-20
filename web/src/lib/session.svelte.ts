import type { Me, PublicConfig } from './types';

const defaultConfig: PublicConfig = {
	base_url: '',
	ai_enabled: false,
	registration_open: true,
	free_limits: { stacks: 5, channels: 5 },
	imprint_html: '',
	privacy_html: ''
};

class Session {
	me = $state<Me | null>(null);
	config = $state<PublicConfig>(defaultConfig);
	loaded = $state(false);

	async load() {
		const [cfg, me] = await Promise.all([
			fetch('/v1/config', { credentials: 'same-origin' })
				.then((r) => (r.ok ? (r.json() as Promise<PublicConfig>) : null))
				.catch(() => null),
			fetch('/v1/me', { credentials: 'same-origin' })
				.then((r) => (r.ok ? (r.json() as Promise<Me>) : null))
				.catch(() => null)
		]);
		if (cfg) this.config = { ...defaultConfig, ...cfg };
		this.me = me;
		this.loaded = true;
	}

	/** Re-fetch /v1/me (e.g. after creating a stack to refresh usage counters). */
	async refreshMe() {
		try {
			const r = await fetch('/v1/me', { credentials: 'same-origin' });
			this.me = r.ok ? ((await r.json()) as Me) : null;
		} catch {
			/* keep old value */
		}
	}
}

export const session = new Session();
