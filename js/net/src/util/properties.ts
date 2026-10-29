import type { ObjectProperties } from "../group.ts";

/**
 * The cache bytes a frame's Object Properties cost, so they share the payload's budget: each id
 * and varint as 8 bytes, a byte value as its length.
 */
export function propertyBytes(properties: ObjectProperties | undefined): number {
	if (properties === undefined) return 0;
	let bytes = 0;
	for (const value of properties.values()) bytes += 8 + (typeof value === "bigint" ? 8 : value.byteLength);
	return bytes;
}
