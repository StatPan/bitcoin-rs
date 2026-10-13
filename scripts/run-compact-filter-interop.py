#!/usr/bin/env python3
"""Run isolated Core/bitcoin-rs/Kyoto compact-filter evidence on loopback.

Builds and installation are deliberately separate. See
tools/compact-filter-interop/README.md for the locked client build.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from p2p_compact_filter_probe import Peer, require, run as wire_run

REPO = Path(__file__).resolve().parents[1]
INDEX = "basic block filter index"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def free_ports(count: int) -> list[int]:
    # Hold all reservations together so the OS cannot select a duplicate port.
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sockets.append(sock)
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def atomic_write(path: Path, report: dict) -> None:
    temporary = path.with_name(f".{path.name}.{report['run_id']}.tmp")
    with temporary.open("w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def footprint(root: Path) -> dict:
    """One closed-directory observation; apparent and allocated bytes differ."""
    if not root.exists():
        return {"present": False, "logical_bytes": 0, "allocated_bytes": 0}
    logical = allocated = 0
    seen = set()
    for path in [root, *root.rglob("*")]:
        stat = path.lstat()
        identity = (stat.st_dev, stat.st_ino)
        if identity not in seen:
            seen.add(identity)
            logical += stat.st_size
            allocated += stat.st_blocks * 512
    return {"present": True, "logical_bytes": logical, "allocated_bytes": allocated}


def stop_process(process, label: str, request=None, timeout: float = 20) -> list[str]:
    """Stop only a process we launched; forced exit can never yield a pass."""
    errors = []
    if process.poll() is None:
        try:
            if request is None:
                process.send_signal(signal.SIGINT)
            else:
                request()
        except Exception as error:
            errors.append(f"{label}: shutdown request failed: {error}")
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            errors.append(f"{label}: forced kill after {timeout:g}s")
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                errors.append(f"{label}: not reaped after kill")
    if process.returncode != 0:
        errors.append(f"{label}: exit {process.returncode}")
    return errors


class Harness:
    def __init__(self, args):
        self.args = args
        parent = args.workdir.resolve() if args.workdir else None
        if parent:
            parent.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="compact-filter-interop-", dir=parent))
        self.evidence = args.evidence.resolve() if args.evidence else self.work / "evidence.json"
        self.evidence.parent.mkdir(parents=True, exist_ok=True)
        # Refuse stale evidence instead of overwriting another run's pass.
        with self.evidence.open("x"):
            pass
        self.started = time.monotonic()
        self.deadline = self.started + args.timeout_seconds
        self.phase_started = self.started
        self.core = self.candidate = None
        self.cleanup_errors = []
        self.report = {
            "schema": "bitcoin-rs-compact-filter-interop-v1",
            "run_id": uuid.uuid4().hex,
            "started_unix_seconds": time.time(),
            "workdir": str(self.work),
            "evidence_path": str(self.evidence),
            "invocation": [sys.executable, *sys.argv],
            "timeout_seconds": args.timeout_seconds,
            "status": "incomplete",
            "passed": False,
            "checks_completed": False,
            "clean_shutdown": False,
            "active_phase": "setup",
            "phases": [],
            "commands": [],
        }
        self.checkpoint()
        self.coredata = self.work / "core"
        self.rsdata = self.work / "rs"
        self.coredata.mkdir()
        self.rsdata.mkdir()
        self.crpc, self.cp2p, self.rrpc, self.rp2p = free_ports(4)

    def remaining(self, limit: float = 90) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("overall interoperability deadline reached")
        return min(limit, remaining)

    def checkpoint(self):
        self.report["elapsed_seconds"] = time.monotonic() - self.started
        atomic_write(self.evidence, self.report)

    def phase(self, name):
        self.report["active_phase"] = name
        self.phase_started = time.monotonic()
        self.checkpoint()
        print(f"PHASE {name}", flush=True)

    def complete(self, **details):
        self.report["phases"].append({
            "name": self.report["active_phase"],
            "seconds": time.monotonic() - self.phase_started,
            **details,
        })
        self.checkpoint()

    def command(self, args, log_name):
        self.report["commands"].append({
            "phase": self.report["active_phase"], "argv": list(args), "log": log_name,
        })
        self.checkpoint()
        with (self.work / log_name).open("w") as stream:
            return subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT)

    def call(self, port, authentication, method, *params, cleanup=False):
        connection = http.client.HTTPConnection(
            "127.0.0.1", port, timeout=5 if cleanup else self.remaining(15),
        )
        try:
            connection.request(
                "POST", "/",
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}),
                {"Authorization": "Basic " + base64.b64encode(authentication).decode(),
                 "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            decoded = json.loads(response.read())
            if decoded.get("error") is not None:
                raise RuntimeError(f"{method}: {decoded['error']}")
            require(response.status == 200, f"{method}: HTTP {response.status}")
            return decoded["result"]
        finally:
            connection.close()

    def core_rpc(self, method, *params, cleanup=False):
        cookie = (self.coredata / "regtest/.cookie").read_bytes().strip()
        return self.call(self.crpc, cookie, method, *params, cleanup=cleanup)

    def rs_rpc(self, method, *params):
        return self.call(self.rrpc, b"interop:interop", method, *params)

    def wait_for(self, label, predicate):
        deadline = time.monotonic() + self.remaining()
        last = None
        while time.monotonic() < deadline:
            for name, process in [("Core", self.core), ("candidate", self.candidate)]:
                if process is not None and process.poll() is not None:
                    raise RuntimeError(f"{name} exited during {label}: {process.returncode}")
            try:
                if predicate():
                    return
            except Exception as error:
                last = str(error)
            time.sleep(min(0.1, self.remaining()))
        raise TimeoutError(f"{label}: {last}")

    def filters_ready(self, rpc):
        return rpc("getindexinfo").get(INDEX, {}).get("synced", False)

    def start_candidate(self, enabled, label):
        command = [
            self.binaries["candidate"], "--network", "regtest", "--data-dir", str(self.rsdata),
            "--rpc-bind", f"127.0.0.1:{self.rrpc}", "--rpc-user", "interop",
            "--rpc-password", "interop", "--p2p-listen", f"127.0.0.1:{self.rp2p}",
            "--connect", f"127.0.0.1:{self.cp2p}", "--dns-seeds-enabled=false",
            "--dbcache-mb", "64", "--log-level", "info",
        ]
        if enabled:
            command += ["--blockfilterindex=basic", "--peerblockfilters"]
        self.candidate_label = label
        self.candidate = self.command(command, f"candidate-{label}.log")
        self.wait_for("candidate RPC", lambda: self.rs_rpc("getblockchaininfo")["chain"] == "regtest")
        self.wait_for("candidate tip", lambda: self.rs_rpc("getbestblockhash") == self.core_rpc("getbestblockhash"))
        if enabled:
            self.wait_for("candidate filters", lambda: self.filters_ready(self.rs_rpc))

    def record_footprint(self):
        self.report.setdefault("closed_candidate_footprints", []).append({
            "launch": self.candidate_label,
            "after_phase": self.report["active_phase"],
            "datadir": str(self.rsdata),
            "whole_datadir": footprint(self.rsdata),
            "txindex": footprint(self.rsdata / "txindex"),
        })
        self.report["footprint_note"] = (
            "Single-run regtest observations after clean shutdown; logical bytes are st_size, "
            "allocated bytes are st_blocks * 512, including directory entries. "
            "Neither whole-datadir deltas nor sparse logical sizes measure filter-row cost "
            "or representative production overhead."
        )
        self.checkpoint()

    def stop_candidate(self):
        if self.candidate is not None:
            errors = stop_process(self.candidate, "candidate")
            if self.candidate.poll() is not None:
                self.candidate = None
            self.cleanup_errors.extend(errors)
            if errors:
                raise RuntimeError("; ".join(errors))
            self.record_footprint()

    def run_client(self, arguments, label):
        process = self.command([self.binaries["client"], *arguments], f"{label}.log")
        try:
            process.wait(timeout=self.remaining(55))
            require(process.returncode == 0, f"Kyoto client exited {process.returncode}; see {label}.log")
            return (self.work / f"{label}.log").read_text()
        finally:
            if process.poll() is None:
                self.cleanup_errors.extend(stop_process(process, "Kyoto client", timeout=5))

    def wallet(self, port, label, txid):
        height = self.core_rpc("getblockcount")
        tip = self.core_rpc("getbestblockhash")
        funding = self.core_rpc("getblockhash", 102)
        output = self.run_client([
            "sync", str(port), str(self.work / label), txid, str(height), tip, funding,
        ], label)
        results = [json.loads(line[7:]) for line in output.splitlines() if line.startswith("RESULT ")]
        expected = {
            "txid": txid, "height": height, "tip_hash": tip,
            "confirmed_sat": 21_000_000, "total_sat": 21_000_000,
            "confirmation_height": 102, "confirmation_hash": funding,
        }
        require(results == [expected], f"unexpected Kyoto wallet result: {results}")
        return {"result": results[0], "log": f"{label}.log"}

    def identify(self):
        self.binaries = {}
        self.report["artifacts"] = {}
        for label, value in [("core", self.args.bitcoind_command),
                             ("candidate", self.args.bitcoin_rs_command),
                             ("client", self.args.client_command)]:
            path = value.resolve(strict=True)
            require(path.is_file() and os.access(path, os.X_OK), f"not executable: {path}")
            self.binaries[label] = str(path)
            self.report["artifacts"][label] = {"path": str(path), "sha256": sha256(path)}
        for name in ["scripts/run-compact-filter-interop.py", "scripts/p2p_compact_filter_probe.py",
                     "tools/compact-filter-interop/Cargo.toml", "tools/compact-filter-interop/Cargo.lock",
                     "tools/compact-filter-interop/src/main.rs"]:
            self.report["artifacts"][name] = {"sha256": sha256(REPO / name)}
        self.report["client_dependencies"] = {"bdk_kyoto": "0.17.0", "bdk_wallet": "3.1.0", "bip157": "0.6.3"}
        # Source identity is a checkout observation, not a claim that a supplied
        # prebuilt executable was produced from that checkout.
        def git(*args):
            return subprocess.check_output(["git", "-C", str(REPO), *args], timeout=self.remaining(10))
        self.report["source_head"] = git("rev-parse", "HEAD").decode().strip()
        self.report["source_diff_sha256"] = hashlib.sha256(git("diff", "--binary", "HEAD")).hexdigest()
        paths = set(git("diff", "--name-only", "HEAD", "-z").split(b"\0"))
        paths.update(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"))
        self.report["changed_source_sha256"] = {
            os.fsdecode(path): sha256(REPO / os.fsdecode(path))
            for path in sorted(paths) if path and (REPO / os.fsdecode(path)).is_file()
        }
        self.checkpoint()

    def verify_binary_hashes(self):
        self.report["final_binary_sha256"] = {
            label: sha256(Path(path)) for label, path in self.binaries.items()
        }
        for label, digest in self.report["final_binary_sha256"].items():
            require(digest == self.report["artifacts"][label]["sha256"],
                    f"{label} binary changed during the run")

    def exercise(self):
        self.identify()
        self.phase("core_setup")
        self.core = self.command([
            self.binaries["core"], f"-datadir={self.coredata}", "-regtest", "-server=1",
            "-daemon=0", "-listen=1", "-connect=0", "-dnsseed=0", "-discover=0", "-listenonion=0",
            f"-port={self.cp2p}", f"-bind=127.0.0.1:{self.cp2p}", f"-rpcport={self.crpc}",
            "-rpcbind=127.0.0.1", "-blockfilterindex=1", "-peerblockfilters=1",
            "-dbcache=16", "-maxmempool=5", "-par=1", "-fallbackfee=0.0001",
        ], "core.log")
        self.wait_for("Core RPC", lambda: self.core_rpc("getblockchaininfo")["chain"] == "regtest")
        self.report["core_version"] = self.core_rpc("getnetworkinfo")["subversion"]
        require(self.report["core_version"] == "/Satoshi:31.1.0/", "expected pinned Bitcoin Core 31.1")
        self.core_rpc("createwallet", "compact-filter-interop")
        miner = self.core_rpc("getnewaddress")
        self.core_rpc("generatetoaddress", 101, miner)
        address = self.run_client(["address"], "client-address").strip()
        txid = self.core_rpc("sendtoaddress", address, "0.21000000")
        self.core_rpc("generatetoaddress", 1, miner)
        self.wait_for("Core filters", lambda: self.filters_ready(self.core_rpc))
        self.complete(funding_txid=txid)

        self.phase("kyoto_core_baseline")
        self.complete(wallet=self.wallet(self.cp2p, "kyoto-core", txid))
        self.core_rpc("generatetoaddress", 1899, miner)
        self.wait_for("Core filters", lambda: self.filters_ready(self.core_rpc))
        self.phase("wire_core_baseline")
        self.complete(checks=wire_run(self.cp2p, self.core_rpc, deadline=self.deadline))

        self.phase("disabled_ibd")
        self.start_candidate(False, "disabled")
        with Peer(self.rp2p, deadline=self.deadline) as peer:
            require(not peer.services & 64, "disabled candidate advertises filters")
        require(INDEX not in self.rs_rpc("getindexinfo"), "disabled candidate advertises filter index")
        self.complete(services_no_filter=True, index_absent=True)
        self.stop_candidate()

        self.phase("late_enable_backfill")
        self.start_candidate(True, "enabled")
        self.complete(index=self.rs_rpc("getindexinfo"))
        self.phase("rpc_parity")
        for height in range(2002):
            block = self.core_rpc("getblockhash", height)
            require(self.rs_rpc("getblockfilter", block) == self.core_rpc("getblockfilter", block),
                    f"RPC filter/header differs at height {height}")
            self.report["rpc_parity_checked"] = height + 1
            if height % 250 == 0:
                self.checkpoint()
        self.complete(blocks=2002)
        self.phase("wire_candidate")
        self.complete(checks=wire_run(self.rp2p, self.core_rpc, deadline=self.deadline))
        self.phase("kyoto_candidate")
        self.complete(wallet=self.wallet(self.rp2p, "kyoto-candidate", txid))

        self.phase("clean_restart")
        before = self.rs_rpc("getblockfilter", self.core_rpc("getbestblockhash"))
        self.stop_candidate()
        self.start_candidate(True, "restart")
        require(self.rs_rpc("getblockfilter", self.core_rpc("getbestblockhash")) == before,
                "filter changed across clean restart")
        self.complete()
        self.stop_candidate()
        self.phase("fresh_enabled_ibd")
        self.rsdata = self.work / "rs-fresh-enabled"
        self.rsdata.mkdir()
        self.start_candidate(True, "fresh-enabled")
        self.complete(tip=self.rs_rpc("getbestblockhash"), index=self.rs_rpc("getindexinfo"))

        self.phase("reorg")
        stale = self.core_rpc("getblockhash", 2001)
        fork = self.core_rpc("getblockhash", 2000)
        self.core_rpc("invalidateblock", fork)
        # A distinct coinbase script prevents reproducing the invalidated block
        # when generation happens within the same timestamp second.
        alternate_miner = self.core_rpc("getnewaddress")
        self.core_rpc("generatetoaddress", 3, alternate_miner)
        require(self.core_rpc("getblockhash", 2000) != fork, "Core did not create a new branch")
        self.wait_for("reorg tip", lambda: self.rs_rpc("getbestblockhash") == self.core_rpc("getbestblockhash"))
        self.wait_for("reorg filters", lambda: self.filters_ready(self.rs_rpc))
        for height in [1999, 2000, 2001, 2002]:
            block = self.core_rpc("getblockhash", height)
            require(self.rs_rpc("getblockfilter", block) == self.core_rpc("getblockfilter", block),
                    f"replacement filter/header differs at height {height}")
        require(self.rs_rpc("getblockfilter", stale) == self.core_rpc("getblockfilter", stale),
                "retained stale-branch filter differs from Core")
        self.complete(
            height=self.rs_rpc("getblockcount"), old_branch_tip=stale, old_fork_block=fork,
            new_branch_tip=self.core_rpc("getbestblockhash"), new_fork_block=self.core_rpc("getblockhash", 2000),
            stale_filter_retained=True,
            kyoto_fresh_replacement_chain_rescan=self.wallet(self.rp2p, "kyoto-replacement", txid),
        )
        require(self.core.poll() is None and self.candidate.poll() is None, "node exited before cleanup")
        self.verify_binary_hashes()
        self.report["checks_completed"] = True

    def cleanup(self):
        # Stop/reap both owned nodes before footprint traversal or evidence I/O.
        self.report["active_phase"] = "cleanup"
        candidate_stopped = False
        if self.candidate is not None:
            try:
                errors = stop_process(self.candidate, "candidate")
                self.cleanup_errors.extend(errors)
                candidate_stopped = not errors
            except Exception as error:
                self.cleanup_errors.append(f"candidate cleanup failed: {error}")
        if self.core is not None:
            try:
                self.cleanup_errors.extend(stop_process(
                    self.core, "Core", lambda: self.core_rpc("stop", cleanup=True),
                ))
            except Exception as error:
                self.cleanup_errors.append(f"Core cleanup failed: {error}")
        if candidate_stopped:
            try:
                self.record_footprint()
            except Exception as error:
                self.cleanup_errors.append(f"closed candidate footprint failed: {error}")
        self.report["cleanup_errors"] = self.cleanup_errors
        self.report["clean_shutdown"] = not self.cleanup_errors
        self.report["passed"] = (
            self.report["checks_completed"]
            and not self.cleanup_errors
            and "error" not in self.report
            and "failed_phase" not in self.report
        )
        self.report["status"] = "passed" if self.report["passed"] else "failed"
        self.checkpoint()


def positive_seconds(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return seconds


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind-command", required=True, type=Path, help="Core 31.1 executable path")
    parser.add_argument("--bitcoin-rs-command", type=Path, default=REPO / "target/release/bitcoin-rs")
    parser.add_argument("--client-command", type=Path, default=REPO / "tools/compact-filter-interop/target/debug/compact-filter-interop-probe")
    parser.add_argument("--workdir", type=Path, help="parent for a NEW retained per-run directory")
    parser.add_argument("--evidence", type=Path, help="new evidence file; existing paths are refused")
    parser.add_argument("--timeout-seconds", type=positive_seconds, default=600, help="overall test deadline, excluding bounded cleanup (default: 600)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if os.name != "posix":
        raise RuntimeError("this runner requires POSIX process signals")
    harness = Harness(args)
    print(f"workdir: {harness.work}\nevidence: {harness.evidence}", flush=True)

    def interrupted(signum, _frame):
        raise TimeoutError(f"run interrupted by signal {signum}")

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
    signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds)
    try:
        harness.exercise()
    except BaseException as error:
        harness.report["failed_phase"] = harness.report["active_phase"]
        harness.report["error"] = repr(error)
        print(f"FAILED: {error}", file=sys.stderr, flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        # Give owned children their bounded shutdown window even on interruption.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            harness.cleanup()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    print(f"{harness.report['status']}: {harness.evidence}", flush=True)
    return 0 if harness.report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
