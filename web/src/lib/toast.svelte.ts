export type ToastKind = 'info' | 'success' | 'error';

export interface Toast {
	id: number;
	kind: ToastKind;
	message: string;
	href?: string;
	linkText?: string;
}

let nextId = 1;

class Toasts {
	items = $state<Toast[]>([]);

	push(message: string, kind: ToastKind = 'info', opts: { href?: string; linkText?: string; timeout?: number } = {}) {
		const id = nextId++;
		this.items.push({ id, kind, message, href: opts.href, linkText: opts.linkText });
		const timeout = opts.timeout ?? (kind === 'error' ? 8000 : 5000);
		if (timeout > 0) setTimeout(() => this.dismiss(id), timeout);
	}

	dismiss(id: number) {
		this.items = this.items.filter((t) => t.id !== id);
	}
}

export const toasts = new Toasts();
export const toast = {
	info: (m: string, o?: Parameters<Toasts['push']>[2]) => toasts.push(m, 'info', o),
	success: (m: string, o?: Parameters<Toasts['push']>[2]) => toasts.push(m, 'success', o),
	error: (m: string, o?: Parameters<Toasts['push']>[2]) => toasts.push(m, 'error', o)
};
