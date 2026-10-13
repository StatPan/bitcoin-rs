"""Offline safety regressions for the compact-filter interoperability harness."""

import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import p2p_compact_filter_probe as probe

SPEC = importlib.util.spec_from_file_location("compact_filter_runner", SCRIPTS / "run-compact-filter-interop.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import compact-filter runner")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FakeSocket:
    def __init__(self, payload):
        self.payload = payload
        self.sent = []

    def recv(self, count):
        part, self.payload = self.payload[:count], self.payload[count:]
        return part

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        pass


def peer_with(payload):
    peer = probe.Peer.__new__(probe.Peer)
    peer.sock = FakeSocket(payload)
    peer.timeout = 30
    peer.run_deadline = float("inf")
    peer.deadline = float("inf")
    return peer


class WireTest(unittest.TestCase):
    def test_canonical_compact_sizes(self):
        for value in [0, 252, 253, 65535, 65536, 2**32]:
            encoded = probe.compact_size(value)
            self.assertEqual(probe.read_compact_size(encoded, 0), (value, len(encoded)))

    def test_malformed_compact_sizes(self):
        for data in [b"", b"\xfd", b"\xfe\x00", b"\xff\x00", b"\xfd\x01\x00",
                     b"\xfe\xff\xff\x00\x00", b"\xff" + bytes(8)]:
            with self.subTest(data=data), self.assertRaises(probe.ProtocolError):
                probe.read_compact_size(data, 0)

    def test_clean_eof_is_not_truncation(self):
        with self.assertRaises(probe.CleanEOF):
            peer_with(b"").recv()
        wire = probe.frame("cfilter", b"abc")
        for truncated in [wire[:1], wire[:23], wire[:24], wire[:-1]]:
            with self.subTest(truncated=truncated), self.assertRaises(probe.ProtocolError):
                peer_with(truncated).recv()

    def test_malformed_frames_fail(self):
        wire = probe.frame("cfilter", b"abc")
        invalid = [b"BAD!" + wire[4:], wire[:-1] + b"X",
                   wire[:16] + struct.pack("<I", 4_000_001) + wire[20:],
                   wire[:4] + b"cf\0ilter\0\0\0\0" + wire[16:]]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(probe.ProtocolError):
                peer_with(data).recv()

    def test_unexpected_filter_response_is_rejected(self):
        with self.assertRaisesRegex(probe.ProtocolError, "unexpected cfheaders"):
            peer_with(probe.frame("cfheaders", b"")).wait("cfilter")

    def test_extra_filter_response_at_barrier_is_rejected(self):
        with self.assertRaisesRegex(probe.ProtocolError, "unexpected cfilter"):
            peer_with(probe.frame("cfilter", b"")).barrier()

    def test_barrier_checks_nonce(self):
        with self.assertRaisesRegex(probe.ProtocolError, "wrong barrier nonce"):
            peer_with(probe.frame("pong", bytes(8))).barrier()

    def test_peer_pings_cannot_extend_deadline(self):
        peer = peer_with(probe.frame("ping", bytes(8)) * 10)
        peer.deadline = 5
        with mock.patch.object(probe.time, "monotonic", side_effect=range(1, 20)):
            with self.assertRaisesRegex(TimeoutError, "absolute wire deadline"):
                peer.recv()
        self.assertEqual(peer.deadline, 5)
        self.assertEqual(len(peer.sock.sent), 1)

    def test_operation_cannot_extend_overall_deadline(self):
        peer = peer_with(b"")
        peer.run_deadline = 10
        with mock.patch.object(probe.time, "monotonic", return_value=9):
            peer.send("ping", bytes(8))
        self.assertEqual(peer.deadline, 10)

    def test_optimized_python_keeps_validation(self):
        result = subprocess.run(
            [sys.executable, "-O", "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "from p2p_compact_filter_probe import require; require(False, 'still checked')",
             str(SCRIPTS)], capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still checked", result.stderr)


class RunnerTest(unittest.TestCase):
    def make_harness(self, parent, evidence=None):
        args = runner.parse_args(["--bitcoind-command", "/unused", "--workdir", str(parent)]
                                 + (["--evidence", str(evidence)] if evidence else []))
        return runner.Harness(args)

    def test_fresh_directories_preserve_existing_data_and_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "operator-data"
            sentinel.write_text("preserve")
            first = self.make_harness(root)
            second = self.make_harness(root)
            self.assertNotEqual(first.work, second.work)
            self.assertEqual(list(first.coredata.iterdir()), [])
            self.assertEqual(sentinel.read_text(), "preserve")
            evidence = json.loads(first.evidence.read_text())
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["status"], "incomplete")
            with self.assertRaises(FileExistsError):
                self.make_harness(root, first.evidence)
            self.assertEqual(json.loads(first.evidence.read_text()), evidence)

    def test_forced_shutdown_is_failed_and_bounded(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.returncode = -9
        process.wait.side_effect = [subprocess.TimeoutExpired("node", 20), -9]
        errors = runner.stop_process(process, "candidate")
        process.send_signal.assert_called_once_with(signal.SIGINT)
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=20), mock.call(timeout=5)])
        self.assertTrue(any("forced kill" in error for error in errors))
        self.assertTrue(any("exit -9" in error for error in errors))

    def test_failed_shutdown_request_uses_owned_process(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.returncode = 0
        errors = runner.stop_process(process, "Core", mock.Mock(side_effect=OSError("RPC failed")))
        process.terminate.assert_called_once_with()
        self.assertTrue(any("RPC failed" in error for error in errors))

    def test_success_waits_for_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = self.make_harness(Path(temporary))
            harness.report["checks_completed"] = True
            harness.checkpoint()
            self.assertFalse(json.loads(harness.evidence.read_text())["passed"])
            harness.cleanup()
            evidence = json.loads(harness.evidence.read_text())
            self.assertEqual(evidence["status"], "passed")
            self.assertTrue(evidence["clean_shutdown"])

    def test_recorded_failure_prevents_success_after_completed_checks(self):
        for key in ["error", "failed_phase"]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                harness = self.make_harness(Path(temporary))
                harness.report["checks_completed"] = True
                harness.report[key] = "interrupted after final check"
                harness.cleanup()
                evidence = json.loads(harness.evidence.read_text())
                self.assertEqual(evidence["status"], "failed")
                self.assertFalse(evidence["passed"])

    def test_main_interruption_after_completed_checks_is_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = self.make_harness(Path(temporary))

            def interrupt_after_checks():
                harness.report["checks_completed"] = True
                raise TimeoutError("interrupted after final check")

            with mock.patch.object(runner, "Harness", return_value=harness), \
                    mock.patch.object(harness, "exercise", side_effect=interrupt_after_checks):
                status = runner.main(["--bitcoind-command", "/unused"])
            self.assertEqual(status, 1)
            evidence = json.loads(harness.evidence.read_text())
            self.assertEqual(evidence["status"], "failed")
            self.assertTrue(evidence["checks_completed"])
            self.assertTrue(evidence["clean_shutdown"])
            self.assertFalse(evidence["passed"])
            self.assertIn("interrupted after final check", evidence["error"])

    def test_cleanup_failure_prevents_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = self.make_harness(Path(temporary))
            harness.report["checks_completed"] = True
            harness.core = mock.Mock()
            with mock.patch.object(runner, "stop_process", return_value=["forced kill"]):
                harness.cleanup()
            evidence = json.loads(harness.evidence.read_text())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(evidence["passed"])
            self.assertFalse(evidence["clean_shutdown"])

    def test_checkpoint_failure_does_not_skip_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = self.make_harness(Path(temporary))
            harness.candidate = mock.Mock()
            harness.core = mock.Mock()
            with mock.patch.object(harness, "checkpoint", side_effect=OSError("disk full")), \
                    mock.patch.object(runner, "stop_process", return_value=["failed"]) as stop:
                with self.assertRaisesRegex(OSError, "disk full"):
                    harness.cleanup()
            self.assertEqual(stop.call_count, 2)
            self.assertFalse(harness.report["passed"])

    def test_binary_changes_are_rejected_at_end(self):
        for changed in [None, "core", "candidate", "client"]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                harness = self.make_harness(root)
                harness.binaries = {}
                harness.report["artifacts"] = {}
                for label in ["core", "candidate", "client"]:
                    path = root / label
                    path.write_bytes(label.encode())
                    harness.binaries[label] = str(path)
                    harness.report["artifacts"][label] = {"sha256": runner.sha256(path)}
                if changed:
                    (root / changed).write_bytes(b"replacement binary")
                    with self.assertRaisesRegex(probe.ProtocolError, f"{changed} binary changed"):
                        harness.verify_binary_hashes()
                else:
                    harness.verify_binary_hashes()
                    self.assertEqual(len(harness.report["final_binary_sha256"]), 3)

    def test_cleanup_stops_both_nodes_before_filesystem_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = self.make_harness(Path(temporary))
            harness.candidate = mock.Mock()
            harness.core = mock.Mock()
            order = []

            def stop(_process, label, *args):
                order.append(f"stop {label}")
                return []

            with mock.patch.object(runner, "stop_process", side_effect=stop), \
                    mock.patch.object(harness, "record_footprint", side_effect=lambda: order.append("footprint")), \
                    mock.patch.object(harness, "checkpoint", side_effect=lambda: order.append("checkpoint")):
                harness.cleanup()
            self.assertEqual(order, ["stop candidate", "stop Core", "footprint", "checkpoint"])

    def test_sparse_footprint_keeps_both_sizes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "sparse"
            with path.open("wb") as stream:
                stream.truncate(64 * 1024 * 1024)
            metric = runner.footprint(root)
            self.assertGreaterEqual(metric["logical_bytes"], 64 * 1024 * 1024)
            self.assertEqual(metric["allocated_bytes"],
                             (root.stat().st_blocks + path.stat().st_blocks) * 512)
            self.assertEqual(runner.footprint(root / "absent")["present"], False)

    def test_nonfinite_and_nonpositive_timeout_is_rejected(self):
        for timeout in ["nan", "inf", "-1", "0"]:
            with self.subTest(timeout=timeout), self.assertRaises(Exception):
                runner.positive_seconds(timeout)


if __name__ == "__main__":
    unittest.main()
