#!/usr/bin/env python3
"""Find corrupted streams that trigger the T1 'code-block data exhausted' path."""
import os, random, subprocess, sys, hashlib

BIN = "../build-asan/bin/opj_decompress"
OLD = "./opj_decompress.before"
rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 99)
data = open("test.j2k", "rb").read()
sot = data.find(b"\xff\x90")
hdr_end = sot + 14

found = 0
os.makedirs("degraded", exist_ok=True)
for i in range(3000):
    d = bytearray(data)
    mode = rng.randrange(3)
    if mode == 0:
        p = rng.randrange(hdr_end, len(d))
        d[p] ^= 1 << rng.randrange(8)
    elif mode == 1:
        p = rng.randrange(hdr_end, len(d))
        ln = rng.randrange(1, 32)
        for j in range(p, min(p + ln, len(d))):
            d[j] = rng.randrange(256)
    else:
        for _ in range(rng.randrange(2, 6)):
            p = rng.randrange(hdr_end, len(d))
            d[p] ^= 0xFF
    open("deg_tmp.j2k", "wb").write(bytes(d))
    r = subprocess.run([BIN, "-i", "deg_tmp.j2k", "-o", "deg_new.pgm"],
                       capture_output=True, timeout=30,
                       env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"})
    if r.returncode not in (0, 1) or b"Sanitizer" in r.stderr:
        print(f"[{i}] CRASH rc={r.returncode}", r.stderr[-500:], file=sys.stderr)
        sys.exit(1)
    if b"code-block data exhausted" in r.stderr:
        found += 1
        h = hashlib.sha1(bytes(d)).hexdigest()[:10]
        os.rename("deg_tmp.j2k", f"degraded/deg_{h}.j2k")
        print(f"[{i}] degradation-path hit -> degraded/deg_{h}.j2k", file=sys.stderr)
        if found >= 3:
            break
print(f"done, {found} hits", file=sys.stderr)
