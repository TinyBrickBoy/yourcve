// Types mirroring api/openapi.yaml (components/schemas).

export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export interface Limits {
	stacks: number;
	channels: number;
}

export interface PublicConfig {
	base_url: string;
	ai_enabled: boolean;
	registration_open: boolean;
	free_limits: Limits;
	imprint_html: string;
	privacy_html: string;
}

export interface Me {
	id: number;
	email: string;
	role: 'user' | 'admin';
	plan: 'free' | 'plus';
	created_at: string;
	limits: Limits;
	usage: Limits;
}

export interface Passkey {
	id: number;
	name: string;
	created_at: string;
	last_used_at: string | null;
}

export interface APIKey {
	id: number;
	name: string;
	prefix: string;
	created_at: string;
	last_used_at: string | null;
	key?: string;
}

export interface CVESummary {
	id: string;
	description: string;
	cvss: number | null;
	cvss_version: string | null;
	severity: Severity;
	cwe: string[] | null;
	kev: boolean;
	epss: number | null;
	epss_percentile: number | null;
	published: string | null;
	modified: string | null;
	category: string | null;
	summary: string | null;
}

export interface Product {
	id: number;
	vendor: string;
	name: string;
	ecosystem: string;
	cpe: string | null;
	purl: string | null;
	aliases: string[] | null;
}

export interface Affect {
	product: Product;
	version_start_including: string | null;
	version_start_excluding: string | null;
	version_end_including: string | null;
	version_end_excluding: string | null;
	versions: string[] | null;
	source: 'nvd' | 'osv' | 'cna';
	confirmed: boolean;
}

export interface CVEDetail extends CVESummary {
	title: string | null;
	cvss_vector: string | null;
	kev_added: string | null;
	kev_due: string | null;
	kev_action: string | null;
	references: string[] | null;
	sources: string[] | null;
	ai_model: string | null;
	affects: Affect[] | null;
}

export interface CVESearchResult {
	total: number;
	items: CVESummary[];
}

export interface SemanticResult {
	items: (CVESummary & { distance?: number })[];
}

export interface StackItem {
	id: number;
	product: Product;
	version: string;
}

export interface Stack {
	id: number;
	name: string;
	created_at: string;
	item_count: number;
	open_cves: number;
	critical_cves: number;
	items?: StackItem[];
}

export type CVEStatus = 'open' | 'not_affected' | 'patched';

export interface StackCVE extends CVESummary {
	reason: string;
	confirmed: boolean;
	status: CVEStatus;
	matched_at: string;
}

export interface ImportResult {
	added: number;
	skipped: string[] | null;
	items: StackItem[] | null;
}

export interface ChannelField {
	key: string;
	label: string;
	placeholder?: string;
	secret?: boolean;
	required?: boolean;
	help?: string;
}

export interface ChannelType {
	type: string;
	label: string;
	class: 'free' | 'paid';
	available: boolean;
	fields: ChannelField[] | null;
}

export interface Channel {
	id: number;
	type: string;
	name: string;
	class: 'free' | 'paid';
	verified: boolean;
	enabled: boolean;
	config: Record<string, string> | null;
	created_at: string;
}

export type RuleMode = 'instant' | 'hourly' | 'daily';

export interface RuleInput {
	stack_id?: number;
	channel_id?: number;
	min_cvss?: number;
	kev_only?: boolean;
	min_epss?: number;
	mode?: RuleMode;
	quiet_start?: string | null;
	quiet_end?: string | null;
	timezone?: string;
	include_unconfirmed?: boolean;
	enabled?: boolean;
}

export interface Rule extends Required<RuleInput> {
	id: number;
	stack_name: string;
	channel_name: string;
	channel_type: string;
}

export type DeliveryStatus = 'pending' | 'digest' | 'sent' | 'failed' | 'suppressed';

export interface Delivery {
	id: number;
	cve_id: string;
	stack_id: number;
	stack_name: string;
	channel_id: number;
	channel_name: string;
	occasion: 'new' | 'kev_added' | 'cvss_raised';
	status: DeliveryStatus;
	attempts: number;
	last_error: string | null;
	next_attempt_at: string | null;
	sent_at: string | null;
	created_at: string;
}

export interface Plan {
	id: 'free' | 'plus';
	name: string;
	price: string;
	available: boolean;
	coming_soon: boolean;
	features: string[] | null;
}

export interface AdminStatus {
	sources: {
		source: string;
		cursor: string;
		last_run: string | null;
		last_success: string | null;
		last_error: string | null;
		lag_seconds: number | null;
		items_total: number;
	}[] | null;
	queue: { available: number; running: number; retryable: number; scheduled: number };
	deliveries: { pending: number; failed_24h: number; sent_24h: number };
	recent_failures: Delivery[] | null;
	counts: {
		cves: number;
		products: number;
		users: number;
		stacks: number;
		ai_summaries: number;
		embeddings: number;
	};
}

export interface MatchEvent {
	stack_id: number;
	cve_id: string;
	occasion: string;
}
