import { expect, test } from "bun:test";
import { GroupTooLarge } from "../error.ts";
import { Producer as GroupProducer, MAX_GROUP_CACHE_BYTES } from "../group.ts";
import { hooks } from "../internal.ts";
import { Cursor, encodeVarint, Reader, Writer } from "../stream.ts";
import { Timescale, Timestamp } from "../time.ts";
import { FetchHeader } from "./fetch.ts";
import { decodeObjectTime, encodeObjectExtensions, Frame, Group } from "./object.ts";
import { Version } from "./version.ts";

const VERSION = Version.DRAFT_18;

/** `timestamp` written at `timescale` and read back. */
async function roundtrip(timestamp: Timestamp, timescale: Timescale): Promise<Timestamp | undefined> {
	const properties = await encodeObjectExtensions(timestamp, timescale, VERSION);
	return decodeObjectTime(new Cursor(properties, VERSION), timescale);
}

test("a same-scale timestamp is written exactly, up to the largest a Timestamp holds", async () => {
	for (const value of [0, 1, 9_007_199_254_740_985, Number.MAX_SAFE_INTEGER]) {
		const read = await roundtrip(new Timestamp(value, Timescale.NANO), Timescale.NANO);
		expect(read?.value).toBe(value);
	}
});

test("a timestamp is converted to the track's scale", async () => {
	expect((await roundtrip(Timestamp.fromMillis(1234), Timescale.NANO))?.value).toBe(1_234_000_000);
	expect((await roundtrip(Timestamp.fromMicros(1_500), Timescale.MILLI))?.value).toBe(2);
});

test("a conversion past what a Timestamp holds is refused before anything is written", async () => {
	// 10^10 ms is 10^16 ns, past 2^53.
	await expect(encodeObjectExtensions(Timestamp.fromMillis(10_000_000_000), Timescale.NANO, VERSION)).rejects.toThrow(
		RangeError,
	);
});

test("a data stream's header goes out in one write, stream type included", async () => {
	for (const version of [Version.DRAFT_22]) {
		const chunks: Uint8Array[] = [];
		const writer = new Writer(
			new WritableStream<Uint8Array>({ write: (chunk) => void chunks.push(new Uint8Array(chunk)) }),
			version,
		);

		// Every optional field present, with values past a one-byte varint.
		const group = new Group({
			trackAlias: 1_000_000n,
			groupId: 70_000,
			subGroupId: 300,
			publisherPriority: 200,
			flags: {
				hasExtensions: true,
				hasSubgroup: true,
				hasSubgroupObject: false,
				hasEnd: true,
				hasPriority: true,
				firstObject: true,
			},
		});
		await group.encode(writer, version);
		await new FetchHeader({ requestId: 1_000_000n }).encode(writer, version);
		expect(chunks.length).toBe(2);

		const decoded = await Group.decode(new Reader(undefined, chunks[0], version), version);
		expect(decoded).toEqual(group);

		const fetch = new Reader(undefined, chunks[1], version);
		expect(await fetch.u53()).toBe(FetchHeader.type);
		expect((await FetchHeader.decode(fetch, version)).requestId).toBe(1_000_000n);
		expect(await fetch.done()).toBe(true);
	}
});

// One object of a subgroup stream: Object ID delta 0, its Properties `block`, then `payload`.
function objectWithProperties(block: Uint8Array, payload: Uint8Array): Uint8Array {
	const length = encodeVarint(block.byteLength, VERSION);
	return new Uint8Array([0, ...length, ...block, payload.byteLength, ...payload]);
}

const OBJECT_FLAGS = {
	hasExtensions: true,
	hasSubgroup: false,
	hasSubgroupObject: false,
	hasEnd: true,
	hasPriority: true,
	firstObject: true,
};

test("a tiny object with a full block of unknown properties retains and charges only LOC's", () => {
	// A Timestamp, then about 32K more even ids as two-byte entries, filling the 64 KiB block.
	const block: number[] = [0x10, 5];
	while (block.length < 64 * 1024 - 2) block.push(0x02, 0);
	const payload = new Uint8Array([42]);
	const frame = Frame.decode(
		new Cursor(objectWithProperties(new Uint8Array(block), payload), VERSION),
		OBJECT_FLAGS,
		undefined,
	);
	expect(frame.properties?.size).toBe(1);
	expect(frame.properties?.get(0x10n)).toBe(5n);

	const group = new GroupProducer(0);
	group.writeFrame({ payload, properties: frame.properties });
	// The payload byte plus one id and its varint.
	expect(hooks.groupCacheBytes(group)).toBe(1 + 16);
	group.finish();
});

test("retained property bytes share the group's cache budget with the payload", () => {
	const config = new Uint8Array(60 * 1024);
	const properties = new Map<bigint, bigint | Uint8Array>([[0x0dn, config]]);
	const group = new GroupProducer(0);
	group.writeFrame({ payload: new Uint8Array([1]), properties });
	expect(hooks.groupCacheBytes(group)).toBe(1 + 8 + config.byteLength);
	// One-byte payloads, each pinning 60 KiB of config, still run out of room.
	expect(() => {
		for (let i = 0; i < MAX_GROUP_CACHE_BYTES / config.byteLength + 1; i++) {
			group.writeFrame({ payload: new Uint8Array([1]), properties });
		}
	}).toThrow(GroupTooLarge);
});
