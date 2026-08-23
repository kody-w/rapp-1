#!/usr/bin/env python3
"""Exercise SQLiteCardState restart, thread, process, and sequence linearization.

Run from the repository root:
  python3 vectors/rappid-card/concurrency_check.py --state-dir .card-concurrency-state
"""
import argparse
import multiprocessing
import os
import pathlib
import queue
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import rapp as R


NOW = "2026-08-21T12:30:00.000Z"
AUTHORITY = (
    "rappid:@example/card-authority:"
    + R.Hb("rapp/1:rappid", bytes.fromhex("00112233445546778899aabbccddeeff"))
)


def _process_claim(path, nonce, connection_id, start, results):
    state = R.SQLiteCardState(path)
    start.wait()
    results.put((connection_id, state.claim_nonce(nonce, connection_id, NOW)))


def _remove_database(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass


def _database(state_dir, name):
    path = os.path.join(state_dir, name + ".sqlite")
    _remove_database(path)
    return path


def restart_check(state_dir):
    path = _database(state_dir, "restart")
    nonce = "restart-crash-nonce-01"
    first = R.SQLiteCardState(path)
    claimed = first.claim_nonce(nonce, "connection-a", NOW)
    restarted = R.SQLiteCardState(path)
    resumed = restarted.claim_nonce(nonce, "connection-a", NOW)
    contender = R.SQLiteCardState(path).claim_nonce(nonce, "connection-b", NOW)
    awake = restarted.mark_awake(nonce, "connection-a", NOW)
    replay = R.SQLiteCardState(path).claim_nonce(nonce, "connection-c", NOW)
    ok = (
        claimed[0] and resumed[0] and not contender[0] and awake[0] and not replay[0]
        and R.SQLiteCardState(path).nonce_state(nonce)["state"] == "awake"
    )
    _remove_database(path)
    return ok


def thread_check(state_dir):
    path = _database(state_dir, "threads")
    R.SQLiteCardState(path)
    nonce = "thread-contention-nonce"
    barrier = threading.Barrier(16)
    results = queue.Queue()

    def claim(index):
        state = R.SQLiteCardState(path)
        barrier.wait()
        results.put(state.claim_nonce(nonce, f"thread-{index}", NOW))

    threads = [threading.Thread(target=claim, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    values = [results.get(timeout=5) for _ in threads]
    ok = all(not thread.is_alive() for thread in threads) and sum(
        1 for accepted, _ in values if accepted) == 1
    _remove_database(path)
    return ok


def process_check(state_dir):
    path = _database(state_dir, "processes")
    R.SQLiteCardState(path)
    nonce = "process-contention-nonce"
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_claim,
            args=(path, nonce, f"process-{index}", start, results),
        )
        for index in range(8)
    ]
    for process in processes:
        process.start()
    start.set()
    values = [results.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
    ok = (
        all(process.exitcode == 0 for process in processes)
        and sum(1 for _, (accepted, _) in values if accepted) == 1
    )
    _remove_database(path)
    return ok


def sequence_check(state_dir):
    path = _database(state_dir, "sequences")
    state = R.SQLiteCardState(path)
    current_hash = "a" * 64
    initial = state.accept_sequence("card-revocation", AUTHORITY, 10, current_hash)
    rollback = state.accept_sequence("card-revocation", AUTHORITY, 9, "b" * 64)
    replay = state.accept_sequence("card-revocation", AUTHORITY, 10, current_hash)
    fork = state.accept_sequence("card-revocation", AUTHORITY, 10, "c" * 64)
    advance = state.accept_sequence("card-revocation", AUTHORITY, 11, "d" * 64)
    ok = (
        initial[0] and not rollback[0] and replay[0] and not fork[0] and advance[0])
    _remove_database(path)
    return ok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    args = parser.parse_args()
    state_dir = os.path.abspath(args.state_dir)
    existed = os.path.isdir(state_dir)
    os.makedirs(state_dir, exist_ok=True)
    checks = {
        "restart/crash-window": restart_check(state_dir),
        "thread contention": thread_check(state_dir),
        "independent-process contention": process_check(state_dir),
        "sequence rollback/fork": sequence_check(state_dir),
    }
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    if not existed:
        os.rmdir(state_dir)
    raise SystemExit(0 if all(checks.values()) else 1)


if __name__ == "__main__":
    main()
