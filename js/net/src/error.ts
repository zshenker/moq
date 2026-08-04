/**
 * Errors, including the code a peer reports when it resets a stream or closes the session.
 *
 * @module
 */

/**
 * Session close codes assigned by MoQ, mirroring the Rust `moq_net::Error::to_code` table
 * (a wire contract shared by every implementation). A {@link RemoteError.code} below 64 came
 * from this table; codes 64 and up are application-chosen (the application's own code plus 64).
 *
 * @public
 */
export const CloseCode = {
	/** The peer is done, not failing: a clean close or a routine unsubscribe. */
	Cancel: 0,
	/** A required extension was not present. */
	RequiredExtension: 1,
	/** The group is older than the latest group and was dropped. */
	Old: 2,
	/** It took too long to open or transmit a stream. */
	Timeout: 3,
	/** The peer's underlying transport failed. */
	Transport: 4,
	/** The peer could not parse a message. */
	Decode: 5,
	/** The peer rejected the credentials or the requested path. Terminal: retrying with the same credentials fails again. */
	Unauthorized: 6,
	/** Version negotiation failed. */
	Version: 9,
	/** An unexpected stream type was received. */
	UnexpectedStream: 10,
	/** An integer exceeded the QUIC varint range. */
	BoundsExceeded: 11,
	/** A duplicate ID was used. */
	Duplicate: 12,
	/** The requested broadcast or track does not exist at the peer. */
	NotFound: 13,
	/** A frame's payload length disagreed with its declared size. */
	WrongSize: 14,
	/** A protocol rule was broken; the session is unusable. */
	ProtocolViolation: 15,
	/** A valid message arrived in a state where it is not allowed. */
	UnexpectedMessage: 16,
	/** The peer was asked for a feature it does not implement. */
	Unsupported: 17,
	/** The peer could not serialize a message for the negotiated version. */
	Encode: 18,
	/** A message carried more parameters than the peer accepts. */
	TooManyParameters: 19,
	/** The peer acted against the role it advertised at SETUP. */
	InvalidRole: 20,
	/** An unrecognized ALPN, so no version could be negotiated. */
	UnknownAlpn: 21,
	/** The producer was dropped without finishing, so the content is incomplete. */
	Dropped: 24,
	/** The handle was already closed. */
	Closed: 25,
	/** The reader fell behind the group's byte budget and a frame was dropped. */
	Lagged: 26,
	/** A frame declared a payload size larger than the receiver accepts. */
	FrameTooLarge: 27,
	/** A frame's timestamp doesn't match its track's negotiated timescale. */
	TimestampMismatch: 29,
	/** A broadcast was requested that nothing announces or serves. */
	Unroutable: 30,
	/** The group was evicted under memory pressure; it can be re-fetched. */
	Evicted: 31,
	/** The session is going away (a GOAWAY was received). */
	GoingAway: 32,
	/** The peer did not close within the GOAWAY drain deadline. */
	GoawayTimeout: 33,
} as const;

/** A wire close code from the reserved table. See {@link CloseCode}. */
export type CloseCode = (typeof CloseCode)[keyof typeof CloseCode];

/**
 * An error the peer reported by resetting a stream or closing the session, carrying the raw
 * code it sent.
 *
 * This deliberately does not translate the code into a local error: the number means whatever
 * the peer says it means ({@link CloseCode} names the reserved range; 64 and up are
 * application-chosen). A read or write rejects with this on every transport, so branch on
 * {@link code} rather than feature-detecting `WebTransportError`, which a non-browser runtime
 * never defines and the WebSocket fallback never throws.
 *
 * Code 0 is what a transport sends when a stream is dropped or aborted with no code of its own.
 *
 * ```ts
 * try {
 *   frame = await group.readFrame();
 * } catch (err) {
 *   if (err instanceof RemoteError && err.code === CloseCode.Old) return;
 *   throw err;
 * }
 * ```
 *
 * @public
 */
export class RemoteError extends Error {
	/** The code the peer sent, verbatim. */
	readonly code: number;

	constructor(code: number, options?: { cause?: unknown; reason?: string }) {
		super(options?.reason ? `remote error: ${code} (${options.reason})` : `remote error: ${code}`, options);
		this.name = "RemoteError";
		this.code = code;
	}
}

/** The WebTransport-shaped fields a stream reset code arrives in. */
type StreamErrorLike = { source?: unknown; streamErrorCode?: unknown };

function streamCode(err: unknown): number | undefined {
	if (typeof err !== "object" || err === null) return undefined;

	const { source, streamErrorCode } = err as StreamErrorLike;
	if (source !== "stream" || typeof streamErrorCode !== "number") return undefined;

	return streamErrorCode;
}

/**
 * Decode a transport failure into a {@link RemoteError} error when it carries a stream reset code,
 * otherwise pass it through.
 *
 * Native WebTransport rejects with a `WebTransportError`; the WebSocket fallback mints an error
 * with the same `source`/`streamErrorCode` fields. Reading the fields rather than the class
 * covers both, and works in a runtime with no `WebTransportError` at all.
 *
 * @internal Called at the transport boundary so the raw error never reaches an application.
 */
export function fromTransport(err: unknown): Error {
	const code = streamCode(err);
	if (code === undefined) return error(err);
	return new RemoteError(code, { cause: err });
}

/**
 * Decode a session close into its terminal error: `null` for a clean close (code 0), otherwise
 * a {@link RemoteError} carrying the code the peer chose (e.g. {@link CloseCode.Unauthorized}
 * for an auth rejection).
 *
 * @internal Applied to the transport's `closed` info so the code survives to the application.
 */
export function fromClose(info: WebTransportCloseInfo): RemoteError | null {
	const code = info.closeCode ?? 0;
	if (code === CloseCode.Cancel) return null;
	return new RemoteError(code, { reason: info.reason });
}

/**
 * Coerce an unknown thrown value into an `Error`.
 *
 * @internal
 */
export function error(err: unknown): Error {
	return err instanceof Error ? err : new Error(String(err));
}

/**
 * Format an error into a non-empty, human-readable string for logging.
 *
 * Safari always leaves `WebTransportError.message` blank, so a bare `err.message` degrades to
 * an empty string and the reason is lost. This falls back to the error type name and appends
 * the WebTransport `source` and application `streamErrorCode`, so the log line always says
 * something.
 */
export function reason(err: unknown): string {
	const e = error(err);

	// WebTransportError carries the failure origin and the peer's application error code,
	// often the only identifying detail since WebKit leaves `message` empty.
	if (typeof WebTransportError !== "undefined" && e instanceof WebTransportError) {
		const parts = [`source=${e.source}`];
		if (e.streamErrorCode !== null) parts.push(`code=${e.streamErrorCode}`);
		const detail = parts.join(" ");
		return e.message ? `${e.message} (${detail})` : `WebTransportError: ${detail}`;
	}

	return e.message || e.name || "unknown error";
}
