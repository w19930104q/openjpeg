#!/usr/bin/env python3
"""Fuzz opj_decompress over multiple seed files; report crashes (ASan/assert/signal)."""
import os, random, subprocess, sys, hashlib, glob

BIN = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 300
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
SRCS = sorted(glob.glob("t_*.j2k")) + ["test.j2k"]

os.makedirs("crashes", exist_ok=True)
rng = random.Random(SEED)
total_crashes = 0
for src in SRCS:
    data = open(src, "rb").read()
    sot = data.find(b"\xff\x90")
    hdr_end = sot + 14 if sot >= 0 else 0
    crashes = 0
    for i in range(N):
        d = bytearray(data)
        mode = rng.randrange(6)
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
        else:  # 0xFF stuffing span in tile data
            p = rng.randrange(hdr_end, len(d))
            ln = rng.randrange(1, min(64, len(d) - p))
            d[p : p + ln] = b"\xff" * ln
        open("fuzz_tmp.j2k", "wb").write(bytes(d))
        r = subprocess.run(
            [BIN, "-i", "fuzz_tmp.j2k", "-o", "fuzz_tmp.pgm"],
            capture_output=True, timeout=60,
            env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
        )
        crash = r.returncode not in (0, 1) or b"Sanitizer" in r.stderr or b"runtime error" in r.stderr or b"Assertion" in r.stderr
        if crash:
            crashes += 1
            total_crashes += 1
            h = hashlib.sha1(bytes(d)).hexdigest()[:12]
            os.rename("fuzz_tmp.j2k", f"crashes/crash_{h}.j2k")
            with open(f"crashes/crash_{h}.log", "wb") as f:
                f.write(b"src=%s mode=%d rc=%d\n" % (src.encode(), mode, r.returncode))
                f.write(r.stderr[-6000:])
            print(f"[{src} #{i}] CRASH mode={mode} rc={r.returncode} -> crashes/crash_{h}.j2k", file=sys.stderr)
            if total_crashes >= 8:
                print("enough crashes", file=sys.stderr)
                sys.exit(0)
    print(f"{src}: {crashes} crashes / {N} iters", file=sys.stderr)
print(f"done: {total_crashes} total crashes", file=sys.stderr)
