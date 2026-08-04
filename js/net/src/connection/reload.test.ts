import { expect, test } from "bun:test";
import { CloseCode, RemoteError } from "../error.ts";
import * as Lite from "../lite/index.ts";
import { createMockTransportPair } from "../mock.ts";
import { accept } from "./index.ts";
import { Reload, type ReloadProps } from "./reload.ts";

async function settle() {
	await new Promise((resolve) => setTimeout(resolve, 0));
}

test("equivalent URL instances do not restart a pending connection", async () => {
	const original = globalThis.WebTransport;
	let connects = 0;

	class PendingWebTransport {
		ready = new Promise<void>(() => {});
		closed = new Promise<void>(() => {});

		constructor() {
			connects++;
		}

		close() {}
	}

	globalThis.WebTransport = PendingWebTransport as unknown as typeof WebTransport;
	const reload = new Reload({
		enabled: true,
		url: new URL("https://example.com/broadcast"),
		websocket: { enabled: false },
	});

	try {
		await settle();
		expect(connects).toBe(1);

		reload.url.set(new URL("https://example.com/broadcast"));
		await settle();
		expect(connects).toBe(1);

		reload.url.set(new URL("https://example.com/other"));
		await settle();
		expect(connects).toBe(2);
	} finally {
		reload.close();
		globalThis.WebTransport = original;
	}
});

test("ReloadProps excludes signal", () => {
	// @ts-expect-error signal is not part of ReloadProps
	const props: ReloadProps = { signal: new AbortController().signal };
	expect(props.enabled).toBeUndefined();
});

test("closing mid-connect aborts the pending attempt", async () => {
	const original = globalThis.WebTransport;
	let closes = 0;

	class PendingWebTransport {
		ready = new Promise<void>(() => {});
		closed = new Promise<void>(() => {});

		close() {
			closes++;
		}
	}

	globalThis.WebTransport = PendingWebTransport as unknown as typeof WebTransport;
	const reload = new Reload({
		enabled: true,
		url: new URL("https://example.com/broadcast"),
		websocket: { enabled: false },
	});

	try {
		await settle();
		expect(closes).toBe(0);

		reload.close();
		await settle();
		expect(closes).toBe(1);
	} finally {
		globalThis.WebTransport = original;
	}
});

test("a peer that severs immediately keeps escalating the backoff", async () => {
	const original = globalThis.WebTransport;
	const url = new URL("https://example.com/");
	const stub = function StubWebTransport() {
		const pair = createMockTransportPair(Lite.ALPN_06_WIP);
		// Sever the session as soon as the server side finishes the handshake.
		void accept(pair.server, url).then((server) => server.close());
		return pair.client;
	};
	globalThis.WebTransport = stub as unknown as typeof WebTransport;

	// Every session dies well within `initial`, so the backoff has to keep escalating
	// and the retry window has to expire. Resetting either on each successful connect
	// reconnects forever at the initial delay and never gives up.
	//
	// `initial` sits far above the in-process handshake so a loaded runner can't make a
	// session look healthy, and the tiny timeout gives up after one backoff.
	const reload = new Reload({
		enabled: true,
		url,
		websocket: { enabled: false },
		delay: { initial: 1000, multiplier: 2, max: 1000, timeout: 1 },
	});
	try {
		await expect(reload.closed).rejects.toThrow();
	} finally {
		reload.close();
		globalThis.WebTransport = original;
	}
});

test("a session rejected as unauthorized stops the reconnect loop", async () => {
	const original = globalThis.WebTransport;
	const url = new URL("https://example.com/");
	const stub = function StubWebTransport() {
		const pair = createMockTransportPair(Lite.ALPN_06_WIP);
		// Reject at the MoQ layer: accept the transport, then close with the auth code,
		// mirroring the relay's Request::close on a 401/403.
		void accept(pair.server, url).then(() => {
			pair.server.close({ closeCode: CloseCode.Unauthorized, reason: "unauthorized" });
		});
		return pair.client;
	};
	globalThis.WebTransport = stub as unknown as typeof WebTransport;

	// Unlimited retries, so the loop stopping at all proves the rejection was classified
	// as terminal: without the decode it retries forever and this test times out.
	const reload = new Reload({
		enabled: true,
		url,
		websocket: { enabled: false },
		delay: { initial: 1, multiplier: 2, max: 1, timeout: 0 },
	});
	try {
		const err = await reload.closed.then(
			() => undefined,
			(err: unknown) => err,
		);
		expect(err).toBeInstanceOf(RemoteError);
		expect((err as RemoteError).code).toBe(CloseCode.Unauthorized);
	} finally {
		reload.close();
		globalThis.WebTransport = original;
	}
});
