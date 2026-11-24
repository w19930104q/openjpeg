#!/usr/bin/env python3
"""Fuzz opj_decompress with corrupted codestreams; report crashes (ASan/signal)."""
import os, random, subprocess, sys, hashlib

BIN = sys.argv[1] if len(sys.argv) > 1 else "../build-asan/bin/opj_decompress"
SRC = "test.j2k"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1

data = open(SRC, "rb").read()
# locate tile data region: first SOT marker 0xFF90
sot = data.find(b"\xff\x90")
hdr_end = sot + 14 if sot >= 0 else 0
print(f"file={len(data)} bytes, SOT at {sot}", file=sys.stderr)

os.makedirs("crashes", exist_ok=True)
rng = random.Random(SEED)
crashes = 0
for i in range(N):
    d = bytearray(data)
    mode = rng.randrange(5)
    if mode == 0:  # single byte flip in tile data
        p = rng.randrange(hdr_end, len(d))
        d[p] ^= 1 << rng.randrange(8)
    elif mode == 1:  # random byte set, several
        for _ in range(rng.randrange(1, 8)):
            p = rng.randrange(hdr_end, len(d))
            d[p] = rng.randrange(256)
    elif mode == 2:  # truncate
        d = d[: rng.randrange(hdr_end + 1, len(d))]
    elif mode == 3:  # zero a span inside tile data
        p = rng.randrange(hdr_end, len(d))
        ln = rng.randrange(1, min(256, len(d) - p))
        d[p : p + ln] = b"\x00" * ln
    else:  # corrupt header bytes too (anywhere)
        for _ in range(rng.randrange(1, 4)):
            p = rng.randrange(0, len(d))
            d[p] ^= 1 << rng.randrange(8)
    open("fuzz_tmp.j2k", "wb").write(bytes(d))
    r = subprocess.run(
        [BIN, "-i", "fuzz_tmp.j2k", "-o", "fuzz_tmp.pgm"],
        capture_output=True, timeout=30,
        env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
    )
    crash = r.returncode not in (0, 1) or b"Sanitizer" in r.stderr or b"runtime error" in r.stderr
    if crash:
        crashes += 1
        h = hashlib.sha1(bytes(d)).hexdigest()[:12]
        os.rename("fuzz_tmp.j2k", f"crashes/crash_{h}.j2k")
        with open(f"crashes/crash_{h}.log", "wb") as f:
            f.write(b"mode=%d rc=%d\n" % (mode, r.returncode))
            f.write(r.stderr[-4000:])
        print(f"[{i}] CRASH mode={mode} rc={r.returncode} -> crashes/crash_{h}.j2k", file=sys.stderr)
        if crashes >= 5:
            break
print(f"done: {crashes} crashes in {i+1} iters", file=sys.stderr)
