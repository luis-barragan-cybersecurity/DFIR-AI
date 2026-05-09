# Case `dfrws-2008-memory`

DFRWS 2008 Forensic Challenge — Linux memory analysis fixture for Volatility 3 happy-path testing in MemoryHound.

## Source

- **Origin (download URL used):** `https://github.com/dfrws/dfrws2008-challenge/raw/master/details/dfrws2008-challenge.zip`
- **Authoritative reference:** `http://old.dfrws.org/2008/challenge/submission.shtml` (Forensic Challenge — DFRWS, 2008)
- **GitHub mirror (canonical):** https://github.com/dfrws/dfrws2008-challenge
- **Format:** raw physical memory dump (extracted from `response_data/challenge.mem` inside the challenge zip), renamed to `input/memory.raw`
- **Size:** 297,795,584 bytes (~284 MiB / ~298 MB)
- **License:** Public — released by DFRWS as a Forensic Challenge dataset, freely distributed for research and analysis (per DFRWS submission.shtml: *"All submitted data... will be published on the DFRWS website."*). DFRWS challenge data is routinely redistributed by NIST CFREDS, Volatility Foundation samples wiki, Forensic Focus, and others without restriction.

## Acquisition (reproducible)

```bash
# Fetch the official zip (from DFRWS GitHub mirror)
curl -L \
  https://github.com/dfrws/dfrws2008-challenge/raw/master/details/dfrws2008-challenge.zip \
  -o /tmp/dfrws2008-challenge.zip

# Verify upstream zip integrity (SHA-1 published on dfrws2008-challenge/details/README.md)
shasum -a 1 /tmp/dfrws2008-challenge.zip
# Expected: 52014e22c843ece2736bce59f652f43e96035825

# Extract memory dump only
unzip -o /tmp/dfrws2008-challenge.zip 'response_data/challenge.mem' -d /tmp/dfrws-extract/

# Move into corpus and rename
mkdir -p corpus/dfrws-2008-memory/input
mv /tmp/dfrws-extract/response_data/challenge.mem corpus/dfrws-2008-memory/input/memory.raw

# Verify extracted dump
shasum -a 256 corpus/dfrws-2008-memory/input/memory.raw
# Expected: 2d3114b42a74a481a02709b16345f37fc489fd24172cb43e6cc6aa2d416675eb
```

### Hashes

| File | Algorithm | Value |
|------|-----------|-------|
| `dfrws2008-challenge.zip` (upstream) | SHA-1 | `52014e22c843ece2736bce59f652f43e96035825` |
| `input/memory.raw` (extracted) | SHA-256 | `2d3114b42a74a481a02709b16345f37fc489fd24172cb43e6cc6aa2d416675eb` |

The upstream SHA-1 matches the value published in the DFRWS 2008 challenge details README, confirming authenticity.

## What This Is (and Isn't)

This is the **canonical DFRWS 2008 Forensic Challenge memory dump**. Important honest disclosures:

- **OS:** Linux — specifically CentOS 5 / kernel `2.6.18-8.1.15.el5`. The DFRWS 2008 challenge focused on Linux memory analysis, not Windows. The accompanying `System.map-2.6.18-8.1.15.el5.zip` is the symbol map needed for full Volatility analysis.
- **NOT Windows XP.** Earlier MemoryHound planning notes (e.g. the parent `corpus/README.md`) listed this case under "(Windows)" — that was a documentation error. Ground truth for this case reflects Linux.
- **Size note:** the raw dump is ~284 MiB, larger than the ~80 MiB sub-plan target. There is no smaller redistribution of the *original DFRWS 2008* dump. We chose authenticity over size — fabricating a synthetic dump would make Volatility produce useless output and invalidate happy-path tests.
- **Volatility 3 compatibility:** Volatility 3 needs a Linux symbol table for this kernel version. The challenge ships a `System.map`; community-converted ISF/JSON symbol files for `2.6.18-8.1.15.el5` are also commonly available. If Sub-Plan 06 needs a Windows-XP-specific happy path instead, supplement this case with a Cridex-class sample later — DFRWS 2008 should not be retired.

## Fallback Used

**No fallback** — the original DFRWS 2008 dump was successfully fetched from the official DFRWS GitHub mirror (`github.com/dfrws/dfrws2008-challenge`). The legacy `old.dfrws.org` URLs return 404 / TLS errors, but the GitHub mirror is the canonical replacement maintained by DFRWS itself.

## Ground Truth Summary

The original challenge questions (per `details/README.md`):

1. What relevant user activity can be reconstructed?
2. Is there evidence of inappropriate or suspicious activity?
3. Is there evidence of collaboration with an outside party?
4. Is there evidence that sensitive data was copied? How was it transferred?

A high-fidelity ground-truth list (winning Cohen/Collett/Walters submission identified): exfiltration of a password-protected ZIP via HTTP cookies; ZIP password break; `gedit` history showing evidence-doctoring; `mc` (Midnight Commander) shell-history showing evidence-prep steps; identity of outside collaborator (Matthew Geiger flagged via XLS metadata).

The structured `ground-truth.json` is currently a **skeleton** — `findings`, `attack_techniques`, and `d3fend_recommendations` are populated empty `[]`. Sub-Plan 06 (accuracy harness) is responsible for populating these against the canonical winning submission report.

## References

- DFRWS 2008 Challenge details: https://github.com/dfrws/dfrws2008-challenge/blob/master/details/README.md
- Winning submission (Cohen, Collett, Walters): https://github.com/dfrws/dfrws2008-challenge/tree/master/results/Cohen_Collet_Walters
- Volatility Linux profiles: https://github.com/volatilityfoundation/volatility/wiki/Linux
