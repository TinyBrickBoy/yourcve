export function fmtDate(s: string | null | undefined): string {
	if (!s) return '–';
	const d = new Date(s);
	if (isNaN(d.getTime())) return s;
	return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtDateTime(s: string | null | undefined): string {
	if (!s) return '–';
	const d = new Date(s);
	if (isNaN(d.getTime())) return s;
	return d.toLocaleString(undefined, {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit'
	});
}

export function fmtRelative(s: string | null | undefined): string {
	if (!s) return '–';
	const d = new Date(s);
	if (isNaN(d.getTime())) return s;
	const diff = (d.getTime() - Date.now()) / 1000;
	const abs = Math.abs(diff);
	const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
	if (abs < 60) return rtf.format(Math.round(diff), 'second');
	if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute');
	if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
	if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day');
	return fmtDate(s);
}

export function fmtDuration(seconds: number | null | undefined): string {
	if (seconds === null || seconds === undefined) return '–';
	const s = Math.max(0, Math.round(seconds));
	if (s < 60) return `${s}s`;
	if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
	if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
	return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

export function fmtCvss(v: number | null | undefined): string {
	return v === null || v === undefined ? '–' : v.toFixed(1);
}

/** EPSS is a probability 0..1; show as percent. */
export function fmtEpss(v: number | null | undefined): string {
	if (v === null || v === undefined) return '–';
	const p = v * 100;
	return (p < 1 ? p.toFixed(2) : p.toFixed(1)) + '%';
}

export function fmtNum(n: number | null | undefined): string {
	if (n === null || n === undefined) return '–';
	return n.toLocaleString();
}

export function truncate(s: string | null | undefined, n: number): string {
	if (!s) return '';
	return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s;
}

export function productLabel(p: { vendor?: string; name: string }): string {
	if (!p.vendor || p.vendor === p.name || p.vendor === '*') return p.name;
	return `${p.vendor} / ${p.name}`;
}

export function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number) {
	let t: ReturnType<typeof setTimeout> | undefined;
	const wrapped = (...args: A) => {
		clearTimeout(t);
		t = setTimeout(() => fn(...args), ms);
	};
	wrapped.cancel = () => clearTimeout(t);
	return wrapped;
}

export async function copyText(text: string): Promise<boolean> {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
}
