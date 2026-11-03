# Driver batch-sends samples

Raw results from the QUIC driver's batch-sends prototype (`Endpoint::batch_sends`).
`samples.jsonl` holds one JSON object per line, and each is one measured run of 15 s
(`wall_s`), after a ramp that brings every session up (`ramp_s`).

`batch_sends` says whether the server batched its sends across connections. The
client never batches, so the flag isolates the server's egress path.

A `label` reads `linux612-batch[-rN]-<batch_sends>-<profile>-<sessions>`. `linux612`
names the kernel (Linux 6.12), and `rN` marks a repeat round of the same runs. The
profile sets the objects each session sends:

- `spec`: 1024 to 4096 byte objects, one per stream, 30 per second.
- `audio`: 100 to 200 byte objects, one per stream, 50 per second.
- `video1`: 3125 to 5208 byte objects, 30 per stream, 30 per second, about 1 Mbps.
- `video3`: 9375 to 15625 byte objects, 30 per stream, 30 per second, about 3 Mbps.

`object_size`, `objects_per_stream`, `rate`, and `sessions` record the same values
in each row.
