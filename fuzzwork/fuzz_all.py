#!/usr/bin/env python3
"""Fuzz opj_decompress over seed corpus; report crashes (ASan/UBSan/assert/signal).
Usage: fuzz_all.py BIN N ITERS_PER_FILE SEED [extra decoder args...]"""
import os, random, subprocess, sys, hashlib, glob

BIN = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 300
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
EXTRA = sys.argv[4:]
SRCS = sorted(glob.glob("t_*.j2k") + glob.glob("t_*.jp2") + ["test.j2k"])

os.makedirs("crashes", exist_ok=True)
rng = random.Random(SEED)
total_crashes = 0
warn_hits = 0
for src in SRCS:
    data = open(src, "rb").read()
    sot = data.find(b"\xff\x90")
    hdr_end = sot + 14 if sot >= 0 else 0
    crashes = 0
    for i in range(N):
        d = bytearray(data)
        mode = rng.randrange(7)
        if mode == 0:
            p = rng.randrange(hdr_end, len(d))
            d[p] ^= 1 << rng.randrange(8)
        elif mode == 1:
            for _ in range(rng.randrange(1, 8)):
                p = rng.randrange(hdr_end, len(d))
                d[p] = rng.randrange(256)
        elif mode == 2:
            d = d[: rng.randrange(hdr_end + 1, len(d))]
        elif mode == 3:
            p = rng.randrange(hdr_end, len(d))
            ln = rng.randrange(1, min(256, len(d) - p))
            d[p : p + ln] = b"\x00" * ln
        elif mode == 4:
            for _ in range(rng.randrange(1, 4)):
                p = rng.randrange(0, len(d))
                d[p] ^= 1 << rng.randrange(8)
        elif mode == 5:
            p = rng.randrange(hdr_end, len(d))
            ln = rng.randrange(1, min(64, len(d) - p))
            d[p : p + ln] = b"\xff" * ln
        else:  # zero tail, keep size
            p = rng.randrange(hdr_end, len(d))
            d[p:] = b"\x00" * (len(d) - p)
        open("fuzz_tmp.j2k", "wb").write(bytes(d))
        r = subprocess.run(
            [BIN, "-i", "fuzz_tmp.j2k", "-o", "fuzz_tmp.raw"] + EXTRA,
            capture_output=True, timeout=60,
            env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
        )
        out = r.stdout + r.stderr
        crash = (r.returncode not in (0, 1) or b"Sanitizer" in out
                 or b"runtime error" in out or b"Assertion" in out)
        if b"code-block data exhausted" in out:
            warn_hits += 1
        if crash:
            crashes += 1
            total_crashes += 1
            h = hashlib.sha1(bytes(d)).hexdigest()[:12]
            os.rename("fuzz_tmp.j2k", f"crashes/crash_{h}.j2k")
            with open(f"crashes/crash_{h}.log", "wb") as f:
                f.write(b"src=%s mode=%d rc=%d extra=%s\n" % (src.encode(), mode, r.returncode, " ".join(EXTRA).encode()))
                f.write(out[-6000:])
            print(f"[{src} #{i}] CRASH mode={mode} rc={r.returncode} -> crashes/crash_{h}.j2k", file=sys.stderr, flush=True)
    print(f"{src}: {crashes} crashes / {N} iters", file=sys.stderr, flush=True)
print(f"done: {total_crashes} total crashes, {warn_hits} degradation-path hits", file=sys.stderr)
