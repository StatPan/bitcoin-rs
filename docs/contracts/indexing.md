# Indexing contract

**Contract version: 1.2** (2026-10-12)

The normative contract for node-owned indexing runtimes, capability gating, and
asynchronous reconciliation across restarts, reorganizations, and selective
rebuilds.

This version adds optional basic-filter ownership and preservation in `IDX-11`.
Changes to these requirements must update their executable proof together.

Owners:
- `DerivedIndexRuntime` and worker state in `crates/index/src/runtime.rs`;
  reconciliation, cursor commits, bounded preparation, and rollback in its
  `reconciliation.rs`, `cursor.rs`, `catch_up.rs`, and `rollback.rs` modules.
- `DerivedIndexQueryEngine` in `crates/index/src/runtime/query.rs` owns the shared
  snapshot gate and public query entrypoints. Its `query/transactions.rs` and
  `query/scripts.rs` modules own exact transaction resolution and script
  traversal; `query.rs` itself owns block identity (`IndexBlockSource`) and
  aggregate work accounting (`QueryBudget`).
- Worker supervision and backend opening in `runtime/lifecycle.rs` and
  `runtime/startup.rs`; startup owns generation-checked publication.
- `IndexWriter`, `IndexReader`, `IndexCapabilities`, `IndexCapability`, `IndexWatermarks`, `IndexWatermark` in `crates/index/src/index.rs` and `crates/index/src/types.rs`
- Capability status: worker-owned `DerivedIndexLifecycle` in
  `crates/index/src/runtime.rs` mapped by `DerivedIndexCapability` onto the
  wire types in `crates/index/src/capabilities.rs`. There is no parallel
  status enum.

## Clauses

### `IDX-08`: Worker wake scheduling

- A wake increments the runtime revision, while wake notifications are
  coalesced: at most one notification need be queued, and a quiet wait observes
  the latest revision rather than the number of notifications.
- A shutdown request takes precedence over a quiet wait or an already-expired
  batch deadline and returns the stopped result without waiting for a wake.
- An expired batch deadline returns the deadline result without waiting for a
  wake. A queued wake interrupts a non-expired wait and returns the woken
  result without changing the deadline.

These are behavioral requirements, not timing guarantees; test durations are
only scheduling mechanics.

### `IDX-01`: Capability configuration and internal enablement

- CLI `--txindex` (env `BITCOIN_RS_TXINDEX`, configuration `txindex=1`) enables
  the `TxLookup` capability in the transaction index store. This builds
  Core-compatible transaction identifier lookup rows (`TxidRow`) and outpoint
  value positions.
- CLI `--scriptindex` / `--script-index` (env `BITCOIN_RS_SCRIPTINDEX`,
  configuration `scriptindex=1`) selects `full` and enables the
  `ScriptHistory` capability. This builds generic scripthash funding rows
  (`ScriptHashRow`), spending rows (`SpendingPrefixRow`), and outpoint spender
  records.
- `scriptindex=utxo` enables only the compact `ScriptLive` view for script
  activity; `scriptindex=full` enables both `ScriptLive` and `ScriptHistory`.
  The historical boolean spellings (`true`, `1`, `yes`) continue to mean
  `full`, and (`false`, `0`, `no`) mean disabled. There is no history-only mode.
- `--blockfilterindex=basic` selects the independent `CompactFilter` capability;
  it defaults off and does not imply transaction or script indexing.
- Enabling any combination of `--txindex`, `--scriptindex`, and
  `--blockfilterindex` spawns exactly one node-owned `DerivedIndexRuntime`
  worker. Aligned capabilities share body loading and an atomic forward batch.
  Transaction/script rows share their parse; optional filter preparation also
  decodes the native block for its authoritative script selection.

### `IDX-02`: Capability advertisement and Core compatibility

- Only explicit `--txindex` advertises the Core `txindex` capability in RPC
  `getindexinfo` and enables historical `getrawtransaction` verbose and raw
  lookups across all confirmed blocks.
- `--scriptindex=utxo` provides only unspent-output queries; `--scriptindex`
  with its historical boolean spelling or `full` additionally provides generic
  script history and spender queries. These modes support Esplora and RPC
  routes without advertising Core `txindex` unless `--txindex` is also set.
- `getindexinfo` reports `synced: true` if and only if the advertised
  capability watermark matches the height and block hash of the active chain tip.
- `getcapabilities` reports one compiled txindex row. A missing worker is
  `enabled: false` / `Disabled`; an attached worker supplies the row through
  `DerivedIndexCapabilitySource`. Proof: `crates/index/src/capabilities.rs` tests
  `missing_source_is_the_disabled_txindex_row`, `attached_source_is_the_worker_row`.

`ScriptLive` is not a duplicate coin table. Its empty-valued key is
`script-hash-prefix || full-outpoint`; the prefix is only a scan accelerator.
Readers resolve each locator against the authoritative UTXO set and exact-check
the full script. Deletes are exact point deletes, so a prefix collision cannot
remove another script's output.

`ScriptHistory` persists funding rows (`ScriptHashRow`) keyed by
`(script_hash_prefix, height)` and spending rows (`SpendingPrefixRow`) keyed by
`(outpoint_prefix, height)`. Because spending rows index the spent outpoint rather
than the original script hash, spend discovery for a script requires first
discovering all funding outpoints for that script. As a result, confirmed history
queries (`confirmed_history`) must discover all funding outputs across the script's
history before resolving spends; reverse-chronological scanning directly at the
storage level cannot be bounded to an initial page without omitting spends of
older funding outputs. However, `confirmed_history` avoids allocating or retaining
unneeded funding record lists when callers only require history records.

### `IDX-03`: Query gating and snapshot consistency

- **Ready invariant**: `ready ⇔ cursor == applied_tip on active chain`, together
  with capability-specific integrity checks. Immutable single-filter reads have
  the narrower retained-record rule in `IDX-11`.
- `DerivedIndexQueryEngine::with_snapshot` and `index_info` gate transaction and
  script reads:
  1. The worker runtime must be healthy (neither `failed` nor `shutdown`).
  2. The applied tip loaded before snapshot creation must match the durable
     capability watermark (`IndexWatermark { height, hash }`) for every consumed
     capability.
  3. The runtime revision (`DerivedIndexRuntime::revision`) and the applied tip
     identity must remain identical before and after snapshot acquisition.
- If an index capability lags behind the tip, is rebuilding, is rolling back
  across a reorg, or experiences a concurrent tip advance during read assembly,
  the query engine refuses the request with `TxQueryError::Retry` or
  `TxQueryError::Unavailable`. Stale, unconfirmed, or torn rows are never
  returned to callers.
- `unspent_outputs` consumes the `ScriptLive` watermark only. The query holds
  chain-transition authority across watermark validation, live locator scan,
  and authoritative UTXO resolution. Apply mutates the UTXO set before
  publishing the applied tip, so a before/after tip comparison cannot exclude
  that window. History and tx-lookup queries do not take the lock. A missing
  locator under an otherwise ready matching watermark is unavailable; a
  compact-prefix collision is filtered by the exact script check.
- A required capability that is not in the configured selection is
  `Unavailable` with a distinct disabled reason. A configured capability
  whose watermark lags is `Retry` (backfilling), never "disabled".

### `IDX-04`: Selective reset preserves sibling readiness

- For transaction/script capabilities, when a watermark experiences corruption, a missing block body
  during reorg rollback, or a schema/version mismatch, the worker resets only
  the degraded capability watermark to `None` and backfills it from the active
  chain.
- Surviving sibling capabilities remain ready: resetting and rebuilding
  `ScriptHistory` leaves `TxLookup` and `ScriptLive` online and serving
  queries as long as their own watermarks match the applied tip, and vice versa.
- Switching `full` → `utxo`, or dropping internal `TxLookup` when explicit
  `--txindex` is off, resets only leftover persisted families. Configured
  families are not rebuilt as a side effect.

### `IDX-05`: Restart reconciliation and schema version refusal

- The `data_dir/txindex` namespace maintains
  durable format versions and capability watermarks (`IndexWatermarks`,
  `ConsumerCursor`).
- A stored schema or format version foreign to this build refuses start for that
  namespace per `docs/policies/db-migration.md` (never an in-place migration).
  `IndexWriter::open` (`crates/index/src/index.rs`) accepts the current
  durability marker only (row-format 5: big-endian heights, 43-byte live rows,
  6-byte positions — format owned by
  `docs/benchmarks/scriptindex-format.md`); every older marker is `IndexError::UnsupportedTxIndexFormatVersion`
  and recovery resets the legacy transaction/script families for rebuild, preserving
  the separately versioned filter records. No in-place upgrade path
  exists. (`IDX-04` selective reset still covers corrupt watermarks, not versions.)
- The dedicated redb store corrects the former 44-byte ScriptLive table
  declaration only when that table is empty. A populated incompatible table
  refuses open without changing its data; the operator must rebuild the derived
  index in a separately named directory. No live-row conversion is performed.
- On node startup, index workers read their persisted watermarks and reconcile
  against `Chainstate::chain_snapshot()` (via `NodeState::chainstate()`):
  - If the watermark is an ancestor of the restored tip, the worker connects
    forward.
  - If the watermark is on an abandoned branch, the worker rolls back to the
    common ancestor and connects forward to the active tip.

### `IDX-10`: Atomic commit durability and recovery

- `IndexWriter` is the sole owner of index mutations. `commit_block` prepares
  all rows and commits them together with the capability watermark in one
  store batch; its successful return is the commit point and implies the rows
  and watermark are durable according to the store's atomic-write guarantee.
- A failed commit must be treated as ambiguous by callers: callers must not
  retry blindly or mutate index column families themselves. The index worker
  re-reads the persisted watermark and either retries from the last confirmed
  contiguous height or resets and rebuilds the affected capability. Storage
  errors are non-retriable by the indexing worker after supervision marks it
  failed; recovery/rebuild owns the reset decision.
- A crash before the atomic batch is visible leaves the previous watermark and
  rows intact; a crash after visibility leaves both the rows and watermark.
  Partial rows without the corresponding watermark are not queryable and are
  reconciled on restart.

### `IDX-09`: Canonical electrs row cardinality

- A committed block emits the canonical electrs rows: one header row, one
  transaction row per indexed transaction, and funding/spending rows for each
  applicable output/input. The golden-row test is the retained contract test
  for these cardinalities.
- `NodeState::open` restores the authenticated checkpoint and, when enabled,
  replays the journal's committed suffix (`docs/contracts/recovery.md`) before
  `NodeState::start_index_workers()` spawns worker threads
  (`crates/node/src/run.rs`), so index workers reconcile against a restored
  active chainstate.

### `IDX-06`: Reorganization rollback and forward reconciliation

- Reorganizations reconcile asynchronously across the chain-event seam
  (`docs/contracts/chain-events.md`). `ChainFollowers` invokes
  `DerivedIndexRuntime::wake()` after each committed connect or disconnect.
- **Disconnect walk**:
  - Height-keyed rows (transaction position rows) are removed using per-block
    watermark identity records to delete exactly the rows contributed by each
    disconnected block from the tip down to the common ancestor.
  - When the rollback depth (watermark height minus common ancestor height)
    exceeds `txindex::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (100 000 blocks),
    the worker routes to `reset_capabilities` and backfills forward instead of
    executing a long block-by-block rollback. Immutable filters instead rewind
    their cursor without deleting records or consulting bodies/undo
    (`docs/benchmarks/index-rollback-rebuild-cutover.md`).
- **Connect walk**:
  - The worker loads bodies from `BlockBodyStore`, constructs bounded forward
    batches (`PreparedBatchLimits`), and commits row mutations and updated
    watermarks in a single atomic store batch per block or block chunk.
  - Live deletes are anchored by the block's authoritative undo scripts;
    same-block create/spend pairs cancel before the anchor is consulted.
    Live inserts use the same admission predicate as the UTXO set, including
    OP_RETURN, oversize-script, and genesis exclusions.
- If a rival reorg or tip extension occurs while a forward batch is being
  prepared, the atomic commit detects the watermark divergence, discards the
  stale prepared batch, and re-plans from the new active tip on the next pass.

### `IDX-07`: Error isolation and supervised rebuild

- If a required block body is missing during a rollback (e.g. an abandoned
  branch block pruned before rollback completed), the worker resets the
  affected capability watermark and initiates a fresh rebuild from the active
  chain.
- A missing or unreadable undo record is fatal only for `ScriptLive`. The
  worker resets that capability and reseeds from the authoritative UTXO view;
  `TxLookup` and `ScriptHistory` continue their body-only rollback.
- When `ScriptLive` has no watermark after restoration or reset, the worker
  rebuilds it by scanning one stable authoritative UTXO view. Each seed batch
  and the watermark stamp are ordinary fenced writes (reset, revision, and
  every capability watermark). The watermark is written only with the last
  batch; without that watermark partial rows are never queryable.
- Index workers execute in supervised threads under `catch_unwind`. A fatal
  storage failure or panic marks the worker as failed (`publish_failed`) and
  stops the worker. Block validation, UTXO commits, and chainstate progress
  continue unimpeded: the apply path never depends on index writes.

### `IDX-11`: Optional BIP158 filters and immutable BIP157 commitments

- `compact_filter::basic_filter` consumes only an already validated block and
  authoritative spent scripts. Same-block inputs resolve against the block's
  outputs before undo. Missing external prevouts refuse preparation; they are
  never silently omitted. Empty scripts are excluded, output scripts starting
  with OP_RETURN are excluded, and elements are deduplicated. Filter output
  selection is distinct from ScriptLive/UTXO admission (including oversized
  scripts and genesis).
- The existing writer, backend, worker and batch fences own filters. There is
  no second UTXO owner, extension framework, scheduler or synchronous filter
  callback on block validation. The default node creates no filter work/store;
  a disabled filter capability does no filter-blob decoding, script lookup or blob
  preparation. An existing enabled transaction/script writer includes the fourth
  watermark in its coherent fence; this small extra metadata operation is not
  a claim of zero overhead for other optional indexes. A malformed optional
  filter watermark is retained as exact opaque fence bytes: transaction/script
  writes preserve it, while enabled filter reconciliation and direct filter
  watermark reads refuse it. Legacy watermark corruption keeps its prior error
  semantics; no cursor is silently repaired or reset.
- Metadata is `F || 0x00 || height(BE,u32) || block_hash`; its fixed 97-byte
  value is `version=2 || parent_hash || filter_hash || filter_header`. The paired
  `F || 0x01 || height || block_hash` value contains only serialized filter bytes.
  Internal hashes use consensus byte order. The two keys, capability watermark
  (`0x00,F`) and cursor disposition publish in one atomic batch. Admission counts
  two rows and 173 bytes plus the filter payload per block.
- Metadata is the sole persisted owner of filter hash/header. Metadata-only
  queries never fetch filter blobs. Full-record reads verify the blob checksum.
  Existing anchors validate their full blob, exact predecessor metadata and
  header recurrence before extension or rewind. Rewind additionally validates
  the target predecessor's full blob; only genesis uses the zero predecessor
  header.
  Unknown record versions and inconsistent/missing components refuse access or
  advancement without migration, repair or implicit reset.
- Reorganizations rewind only the filter watermark. Immutable records remain
  queryable by exact block identity after disconnect; reconnection must reproduce
  both components. Disabling filters preserves their rows and watermark. Legacy
  `reset_index` preserves them. Explicit filter reset invalidates its watermark
  and deletes only the `F` prefix in existing bounded, fenced reset batches.
  This bounds each batch, not total retained historical/stale-branch disk space.
- Late enablement backfills from genesis only when retained block/undo facts can
  produce the full header chain. A history gap is explicit unavailability, never
  a synthetic pruned-prefix filter anchor. Node configuration currently rejects
  `blockfilterindex` with pruning. Filter-specific failures stop only filter
  reconciliation; storage failures retain the existing whole-worker failure rule.
- `CompactFilterQuery` is the only external filter read capability. Single-block
  reads can return valid retained records while indexing lags. P2P ranges require
  a matching active watermark; all reads recheck runtime health, local filter
  refusal, applied tip/revision and requested block eligibility. Plans are anchored
  to the requested stop hash, not changing active-height lookups.
- Readiness additionally validates the exact tip blob and tip/parent metadata.
  It is a bounded integrity probe, not an audit of every historical row; each
  request checks its own records. Streamed filters check outbound headroom before
  each blob and hold only one blob, with count/size/ancestry bounds. Hash/header
  ranges consume fixed metadata, not the unrelated cumulative historical-query
  byte budget.

Proof: `tests/compact_filter.rs` (official BIP158 vectors and prevout edge cases),
`tests/compact_filter_storage.rs` (atomic components/cursor, corruption/version
refusal, prefix reset, branch retention and physical reopen),
`runtime/filter_tests.rs` (worker isolation, reorg and late enablement), and
`runtime/query/filter_tests.rs` (ranges, readiness, streaming and invalidation).

## Live gaps

- **Full-stack crash convergence**: The recovery model across chainstate,
  checkpoints, block bodies, and derived indexes is normative in
  [recovery.md](recovery.md) (`RCV-01`–`RCV-04`); a `kill -9` gate that
  re-applies real block bodies through it is not yet exercised.
## Proven by

- `crates/index/tests/index_roundtrip.rs`
  `commit_golden_blocks_writes_expected_electrs_rows`: electrs family
  occupancy after one atomic `IndexWriter::commit_block` (`IDX-06`).
- `crates/index/src/runtime/recovery_tests.rs`:
  - `index_ahead_of_restored_tip_is_reported_once_and_rewound`
  - `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
  - `pruned_history_rebuilds_from_the_frontier_and_absent_history_waits`
- `crates/index/src/runtime/startup.rs` and
  `crates/index/src/runtime/integration_tests.rs`: lifecycle
  publication, open failure/timeout, and shutdown abandonment.
- `crates/index/src/runtime/query_tests.rs`: query gating, snapshot
  consistency, revision ABA detection, and
  `failed_worker_makes_queries_unavailable` /
  `stopped_worker_makes_queries_unavailable` worker-liveness refusal.
- `crates/index/src/index/tests.rs`: confirmed-body
  serving by height/hash (`IDX-03`, `RCV-01`).
- `crates/chainstate/src/reorg.rs` and the `RCV-08` recovery evidence prove
  bounded disconnect streaming under a retention lease; the departed branch
  is not preloaded.
- `crates/index/src/capabilities.rs` tests `missing_source_is_the_disabled_txindex_row`,
  `attached_source_is_the_worker_row`: `getcapabilities` advertises one
  txindex row from `derived_index_status` (`IDX-02`).

### Query-budget regression evidence

`crates/index/src/runtime/query.rs` tests exercise the shared
historical/live byte budget, independent row/scan/body-read admission limits,
rejection of truncated scans, and non-consuming rejection of over-budget work
(`IDX-03` and the project bounded-resources invariant). No query limit or persisted representation changes.

### Store-open cancellation evidence

The store-open wait polls node shutdown, runtime stop, and generation revocation
at bounded intervals. Once the helper has started, cancellation and timeout are
typed abandoned-open outcomes: startup poisons the namespace before releasing
the worker's claim. Cancellation before helper creation may release normally.
These paths do not cancel the underlying storage-engine call.

Evidence for `IDX-07` abandonment and `IDX-08` shutdown:
`crates/index/src/runtime/startup.rs` tests cover bounded
cancellation, deadline precedence, disconnection, backend error propagation,
namespace poisoning, and clean release. The query-budget limits and on-disk formats are unchanged.
