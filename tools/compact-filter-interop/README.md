# Compact-filter interoperability evidence

This opt-in regtest harness exercises the public RPC/P2P surfaces of a supplied
bitcoin-rs executable against pinned Bitcoin Core 31.1 and a real external
wallet client. It is separate from the fast PR tests. Having these scripts in
the tree is not evidence that a particular candidate binary passed them.

The client uses unmodified `bdk_kyoto = 0.17.0` and `bdk_wallet = 3.1.0`.
`Cargo.lock` pins the transitive graph, including `bip157 = 0.6.3`. Its own
`[workspace]` prevents these dependencies from entering the node workspace.
The public descriptors are test fixtures; never receive real funds with them.

## Run

Requirements: POSIX process signals, Python 3.11+, Git, the repository's Rust
toolchain, and a Core 31.1 executable. The driver does not install or build
anything. From the repository root, one reproducible build/run sequence is:

```sh
cargo build --locked --profile quickstart -p bitcoin-rs \
  --no-default-features --features fjall
cargo build --locked --manifest-path tools/compact-filter-interop/Cargo.toml \
  --target-dir target/compact-filter-interop

python3 scripts/run-compact-filter-interop.py \
  --bitcoind-command "$(scripts/install-bitcoind.sh)" \
  --bitcoin-rs-command target/quickstart/bitcoin-rs \
  --client-command target/compact-filter-interop/debug/compact-filter-interop-probe \
  --workdir target/compact-filter-interop-runs \
  --timeout-seconds 600
```

The installer verifies the pinned archive as described in
[the Core differential contract](../../docs/contracts/core-differential.md).
Executable arguments are literal file paths, not shell command strings. To use
existing builds, pass their paths directly. Keep build commands/logs alongside
the evidence when attributing an executable to a source checkout; the runner
hashes supplied executables but cannot establish how they were built.

`--workdir` is a parent directory: every invocation creates a unique, private
child containing fresh Core/candidate/client state. Existing data is never
reset or deleted. Logs and data are retained on success and failure. The default
evidence path is that child's `evidence.json`. `--evidence PATH` selects a new
file and refuses an existing path, including an old passed result.

All RPC and P2P listeners bind to `127.0.0.1`. Core has discovery, DNS seeds,
external connections, and onion listening disabled; the candidate connects only
to Core with DNS seeds disabled. Kyoto uses `whitelist_only()` with exactly one
loopback peer so gossiped Core addresses cannot mask a candidate failure.

## What a passed run establishes

1. Core mines a payment of exactly 21,000,000 satoshis at height 102. A fresh
   Kyoto wallet scan against Core finds the exact transaction, confirmation
   block/height, best block hash/height, confirmed balance, and total balance.
2. Core extends to height 2001. The same strict wire probe runs against Core
   before it is used to evaluate the candidate.
3. A default-disabled candidate synchronizes without advertising
   `NODE_COMPACT_FILTERS` or the basic-filter index. Restarting that same data
   directory with filters enabled backfills to a ready index.
4. All 2002 filters and filter headers, including genesis, exactly equal Core's
   `getblockfilter` output.
5. Both wire runs check nine groups: service advertisement; 1000 sequential
   filters; 2000 filter hashes plus the previous header; exact checkpoint
   boundaries at 0/999/1000/1001/2000/2001; and clean disconnection without any
   filter response for 1001-filter requests, 2001-header requests, reversed
   ranges, unknown filter types, and unknown stop hashes.
6. A fresh Kyoto scan against the candidate has the same exact wallet result.
   The ready filter survives a clean restart, and a separate fresh candidate
   data directory synchronizes with filters enabled from startup.
7. Core replaces heights 2000–2001 with a three-block branch, reaching 2002.
   The candidate converges to that exact tip; replacement filters/headers and
   the retained stale-branch filter equal Core. Another **fresh** Kyoto wallet
   scans the replacement chain and verifies the exact wallet result.
8. Every owned node exits cleanly. A forced kill, shutdown error, or nonzero
   node exit prevents a passed result.

The replacement-chain wallet check is not a live wallet rollback test. This
small regtest campaign does not establish production performance, pruning
support, crash recovery, exhaustive adversarial behavior, mainnet behavior, or
compatibility with every wallet. Production invariants remain owned by
[the indexing contract](../../docs/contracts/indexing.md).

## Retained run

[The 2026-10-12 record](evidence/regtest-2026-10-12.json) retains a passed
run on upstream base `5dafad023893cda9407396e2923863d88619a6c0` plus the
changed-source hashes. It used Rust 1.99.0, the test-profile native/Fjall
executable, and a 64 MiB candidate cache budget. The record includes exact
binary hashes and all public outcomes; local paths and process argument
arrays are omitted. The original terminal record SHA-256 is retained.
This is a bounded compatibility observation, not a cost-acceptance benchmark.

## Evidence and bounds

The JSON schema is `bitcoin-rs-compact-filter-interop-v1`. A new record begins as
`status: incomplete`, `passed: false`. Atomic checkpoints retain the active
phase, completed checks and partial RPC-parity count. Only completed checks without a recorded error
**and** successful cleanup change it to `status: passed`, `passed: true`,
`checks_completed: true`, `clean_shutdown: true`. Interrupted or failed checks
produce a failed record when cleanup can finish; a hard kill may leave an
incomplete record, which must never be interpreted as a pass.

Evidence records executable SHA-256 values, the manifest/lock/source/probe
hashes, the observed Git HEAD and diff/changed-file hashes, exact subprocess
argument arrays, Core's version, phase timings, wallet results and branch
identities. The three executable hashes are checked again after all live checks;
a changed binary fails the run. Checkout hashes are observations rather than build attestations.
Node/client output is in the named sibling log files. Do not publish node data
directories or RPC cookies when sharing evidence.

After each clean candidate shutdown, `closed_candidate_footprints` records
whole-data-directory and `txindex` logical bytes (`st_size`) separately from
allocated bytes (`st_blocks * 512`). The totals include directory entries and
count hard-linked inodes once. Sparse/preallocated files can have large logical
sizes without corresponding allocation. These are single-run regtest
observations, not filter-row cost estimates or representative overhead claims.

The overall test timeout defaults to 600 seconds. Individual readiness waits,
RPC calls, wire exchanges, and wallet invocations also have finite bounds. Peer
pings cannot refresh an exchange's absolute deadline. Barriers reject extra or
unexpected filter frames; malformed/truncated frames cannot count as a valid
disconnect. Python validation is explicit and remains active under `python -O`.
Cleanup is outside the test deadline: each node gets up to 20 seconds for a
clean exit, then 5 seconds to reap a forced kill (Core's shutdown RPC is bounded
by another 5 seconds). Only processes started by this invocation are signaled.

## Offline harness tests

No Rust build, daemon, network download, or external service is needed:

```sh
python3 -m unittest discover -s scripts/tests -p test_compact_filter_interop.py
python3 -O -m unittest discover -s scripts/tests -p test_compact_filter_interop.py
```

These cover malformed frames/lengths, clean EOF versus truncation, over-response
barriers, deadlines that survive peer pings, optimized-Python validation, fresh
state and stale-evidence protection, bounded shutdown failures, evidence-write
failure during cleanup, terminal interruption, binary changes, and sparse-file
footprint accounting. They verify the
harness's safeguards, not live protocol compatibility.
