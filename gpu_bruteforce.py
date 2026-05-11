"""
bruteforce.py
=============
CPU-only brute-force engines for the XDES-A demo.

DES  → ThreadPoolExecutor (pure Python, all cores)
XDES → ThreadPoolExecutor (Argon2id releases the GIL → true multi-core)

Why ThreadPoolExecutor instead of multiprocessing.Pool?
  Pool workers run in separate processes and must pickle everything.
  argon2-cffi objects and cipher state are NOT pickle-safe → silent hangs
  or ImportErrors in subprocesses.  ThreadPoolExecutor shares the same
  process memory → no pickling → just works.
  DES (pure Python) also benefits because the GIL is released between
  thread switches and the workload is embarrassingly parallel.

Exported symbols (same API as before — ui.py imports these names):
    brute_force_des_gpu(...)
    brute_force_xdes_gpu(...)
"""

from __future__ import annotations

import itertools
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

# ─────────────────────────────────────────────────────────────────────────────
#  Import cipher helpers
# ─────────────────────────────────────────────────────────────────────────────
from cipher import (
    des_encrypt_block,
    _candidate_to_des_key,
    derive_keys,
    xdes_encrypt_block,
    BRUTE_CHARSET_ALPHA,
    BRUTE_CHARSET_ALPHANUM,
    BRUTE_CHARSET_COMMON,
)

# Default worker count — all logical CPU cores
_DEFAULT_WORKERS = os.cpu_count() or 4


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — DES brute force
# ═════════════════════════════════════════════════════════════════════════════

def brute_force_des_gpu(
    target_ct: bytes,
    known_pt: bytes,
    max_len: int,
    charset: str,
    stop_event,
    on_attempt: Callable,
    on_done: Callable,
    num_workers: int = _DEFAULT_WORKERS,
    log_fn: Callable[[str], None] | None = None,
):
    """
    DES brute-force using ThreadPoolExecutor across all CPU cores.
    The 'gpu' suffix is kept for API compatibility with ui.py.
    """
    if log_fn:
        log_fn(f"  →  Using {num_workers} CPU threads for DES\n\n")
    _des_threaded(target_ct, known_pt, max_len, charset,
                  stop_event, on_attempt, on_done, num_workers)


def _des_threaded(target_ct, known_pt, max_len, charset,
                  stop_event, on_attempt, on_done, num_workers):
    pt8       = (known_pt[:8] + bytes(8))[:8]
    attempt   = 0
    start     = time.perf_counter()
    lock      = threading.Lock()
    found_box = [None]

    def _try(candidate):
        if stop_event.is_set() or found_box[0]:
            return candidate, False
        key8 = _candidate_to_des_key(candidate)
        return candidate, des_encrypt_block(pt8, key8) == target_ct

    BATCH = max(num_workers * 4, 64)

    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        batch = []
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if stop_event.is_set() or found_box[0]:
                    break
                batch.append("".join(combo))
                if len(batch) >= BATCH:
                    for fut in as_completed([ex.submit(_try, c) for c in batch]):
                        candidate, found = fut.result()
                        with lock:
                            attempt += 1
                        elapsed = time.perf_counter() - start
                        on_attempt(attempt, candidate, elapsed, found)
                        if found:
                            found_box[0] = candidate
                    batch = []
                    if found_box[0]:
                        break
            if found_box[0] or stop_event.is_set():
                break

        if batch and not found_box[0] and not stop_event.is_set():
            for fut in as_completed([ex.submit(_try, c) for c in batch]):
                candidate, found = fut.result()
                with lock:
                    attempt += 1
                elapsed = time.perf_counter() - start
                on_attempt(attempt, candidate, elapsed, found)
                if found:
                    found_box[0] = candidate

    elapsed = time.perf_counter() - start
    if found_box[0]:
        on_done(True, found_box[0], attempt, elapsed)
    else:
        on_done(False, "", attempt, elapsed)


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — XDES brute force
# ═════════════════════════════════════════════════════════════════════════════

def brute_force_xdes_gpu(
    target_ct: bytes,
    known_pt: bytes,
    argon_salt: bytes,
    max_len: int,
    charset: str,
    stop_event,
    on_attempt: Callable,
    on_done: Callable,
    num_workers: int = _DEFAULT_WORKERS,
    log_fn: Callable[[str], None] | None = None,
):
    """
    XDES-A brute-force using ThreadPoolExecutor across all CPU cores.

    Why threads?
    ─────────────
    argon2-cffi calls into C and RELEASES the GIL during hashing, so
    N threads genuinely run N Argon2id hashes in parallel on N cores.
    multiprocessing.Pool would require pickling argon2-cffi state → broken.
    The 'gpu' suffix is kept for API compatibility with ui.py.
    """
    if log_fn:
        log_fn(f"  →  Using {num_workers} CPU threads "
               f"(Argon2id releases GIL → true multi-core)\n\n")
    _xdes_threaded(target_ct, known_pt, argon_salt, max_len, charset,
                   stop_event, on_attempt, on_done, num_workers)


def _xdes_threaded(target_ct, known_pt, argon_salt, max_len, charset,
                   stop_event, on_attempt, on_done, num_workers):
    attempt   = 0
    start     = time.perf_counter()
    lock      = threading.Lock()
    found_box = [None]
    pt16      = (known_pt + bytes(16))[:16]

    def _try(candidate):
        if stop_event.is_set() or found_box[0]:
            return candidate, False
        # derive_keys → argon2-cffi C extension releases the GIL here
        keys = derive_keys(candidate.encode(), argon_salt)
        ct   = xdes_encrypt_block(pt16, keys)
        return candidate, ct == target_ct

    # Argon2id is slow (~10/s per thread) — keep batches small for UI responsiveness
    BATCH = max(num_workers, 2)

    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        batch = []
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if stop_event.is_set() or found_box[0]:
                    break
                batch.append("".join(combo))
                if len(batch) >= BATCH:
                    futs = [ex.submit(_try, c) for c in batch]
                    for fut in as_completed(futs):
                        candidate, found = fut.result()
                        with lock:
                            attempt += 1
                        elapsed = time.perf_counter() - start
                        on_attempt(attempt, candidate, elapsed, found)
                        if found:
                            found_box[0] = candidate
                    batch = []
                    if found_box[0]:
                        break
            if found_box[0] or stop_event.is_set():
                break

        if batch and not found_box[0] and not stop_event.is_set():
            for fut in as_completed([ex.submit(_try, c) for c in batch]):
                candidate, found = fut.result()
                with lock:
                    attempt += 1
                elapsed = time.perf_counter() - start
                on_attempt(attempt, candidate, elapsed, found)
                if found:
                    found_box[0] = candidate

    elapsed = time.perf_counter() - start
    if found_box[0]:
        on_done(True, found_box[0], attempt, elapsed)
    else:
        on_done(False, "", attempt, elapsed)


# ─────────────────────────────────────────────────────────────────────────────
#  Quick diagnostics  (python gpu_bruteforce.py)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import threading as _t
    print("=" * 60)
    print("  bruteforce.py — diagnostics")
    print("=" * 60)
    print(f"  CPU cores available : {os.cpu_count()}")
    print(f"  Default workers     : {_DEFAULT_WORKERS}")
    print(f"  DES  → ThreadPoolExecutor")
    print(f"  XDES → ThreadPoolExecutor (Argon2id releases GIL)")
    print()

    stop = _t.Event()
    res  = {}

    def _oa(n, c, t, f):
        if n % 100 == 0 or f:
            print(f"  #{n:<5} trying {c!r}  {t:.2f}s {'✓ FOUND' if f else ''}")

    def _od(found, cand, n, t):
        res.update(found=found, cand=cand, n=n, t=t)

    from cipher import des_encrypt_block, _candidate_to_des_key
    secret = "ab"
    pt8    = b"HELLO!!!"
    tct    = des_encrypt_block(pt8, _candidate_to_des_key(secret))
    print(f"  Smoke-test: cracking DES secret {secret!r} ...")
    brute_force_des_gpu(tct, pt8, 2, "abcdefghijklmnopqrstuvwxyz", stop, _oa, _od)
    if res.get("found"):
        print(f"\n  ✓  Cracked: {res['cand']!r} in {res['n']} tries, {res['t']:.2f}s")
    else:
        print(f"\n  ⚠  Not found.")