// Minimal WebAuthn helpers for go-webauthn JSON (base64url encoded binary fields).

export function b64urlToBuf(s: string): ArrayBuffer {
	const pad = '='.repeat((4 - (s.length % 4)) % 4);
	const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
	const bin = atob(b64);
	const buf = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
	return buf.buffer;
}

export function bufToB64url(buf: ArrayBuffer | ArrayBufferView | null | undefined): string {
	if (!buf) return '';
	const bytes =
		buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
	let bin = '';
	for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

type JsonDescriptor = { id: string; type: string; transports?: string[] };

function convertDescriptors(list: JsonDescriptor[] | undefined | null): PublicKeyCredentialDescriptor[] | undefined {
	if (!list) return undefined;
	return list.map((c) => ({
		...c,
		id: b64urlToBuf(c.id),
		type: 'public-key',
		transports: c.transports as AuthenticatorTransport[] | undefined
	}));
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

export function toCreationOptions(json: Json): CredentialCreationOptions {
	const pk = json.publicKey ?? json;
	return {
		publicKey: {
			...pk,
			challenge: b64urlToBuf(pk.challenge),
			user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
			excludeCredentials: convertDescriptors(pk.excludeCredentials)
		}
	};
}

export function toRequestOptions(json: Json): CredentialRequestOptions {
	const pk = json.publicKey ?? json;
	return {
		publicKey: {
			...pk,
			challenge: b64urlToBuf(pk.challenge),
			allowCredentials: convertDescriptors(pk.allowCredentials)
		}
	};
}

export function credentialToJSON(cred: PublicKeyCredential): Record<string, unknown> {
	const r = cred.response;
	const response: Record<string, unknown> = {
		clientDataJSON: bufToB64url(r.clientDataJSON)
	};
	if ('attestationObject' in r) {
		const att = r as AuthenticatorAttestationResponse;
		response.attestationObject = bufToB64url(att.attestationObject);
		if (typeof att.getTransports === 'function') response.transports = att.getTransports();
	}
	if ('authenticatorData' in r) {
		const ass = r as AuthenticatorAssertionResponse;
		response.authenticatorData = bufToB64url(ass.authenticatorData);
		response.signature = bufToB64url(ass.signature);
		if (ass.userHandle) response.userHandle = bufToB64url(ass.userHandle);
	}
	return {
		id: cred.id,
		rawId: bufToB64url(cred.rawId),
		type: cred.type,
		authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
		clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
		response
	};
}

export function passkeysSupported(): boolean {
	return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

/** Turns DOMExceptions from the WebAuthn API into a short user message (null = user cancelled). */
export function webauthnError(e: unknown): string | null {
	if (e instanceof DOMException) {
		if (e.name === 'NotAllowedError' || e.name === 'AbortError') return null;
		if (e.name === 'InvalidStateError') return 'This passkey is already registered.';
		return e.message || e.name;
	}
	return e instanceof Error ? e.message : String(e);
}
