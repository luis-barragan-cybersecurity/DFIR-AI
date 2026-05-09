# Symbol-Table Attribution

This directory vendors a Volatility 3 ISF (Intermediate Symbol File)
symbol table required to analyse the DFRWS 2008 Linux memory dump.

## Vendored File

| Field | Value |
|-------|-------|
| Path | `linux/2.6.18-8.1.15.el5_64.json.xz` |
| Size (compressed) | 194,636 bytes |
| Size (decompressed JSON) | ~4.55 MiB |
| SHA-256 | `c42ef8e865ade04a8a3ec565475bd368c9c14346c73c1137de6dcb048aa8af8f` |
| Vendored date | 2026-05-09 |
| Producer | `dwarf2json` 0.9.0 |
| Source kernel | CentOS 5, kernel `2.6.18-8.1.15.el5` (x86_64) |
| Symbol count | 27,928 symbols, 417 user-defined types |

## Upstream

The file was extracted bit-for-bit from the official Volatility Foundation
sample-symbols bundle:

- **Bundle URL**: <https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip>
- **Bundle entry**: `linux/Centos_2.6.18-8.1.15.el5_2.6.18-8.1.15.el5_x64.json.xz`
- **Renamed to**: `linux/2.6.18-8.1.15.el5_64.json.xz` (matches the kernel banner stamped in the DFRWS 2008 dump)
- **Distributor**: Volatility Foundation (`volatilityfoundation/volatility3`)

We tried `Abyss-W4tcher/volatility3-symbols` first, per the original spec;
that repository covers Ubuntu / Debian / Kali / AlmaLinux / RockyLinux /
macOS only — no CentOS 5 / RHEL 5 kernels. The Volatility Foundation
sample bundle was the canonical source.

## Licensing

The ISF is derived data: `dwarf2json` consumed DWARF debug info compiled
into the CentOS 5 kernel package (GPL-2.0) and emitted a JSON description
of types and symbols. Treat the file as the union of:

- **Volatility Foundation** distribution (Volatility Software License v1.0
  applies to the *project* — but a JSON symbol table is data, not
  executable code, so VSL §3 source-disclosure terms do not apply to
  redistribution of unmodified ISFs).
- **GPL-2.0** for the underlying kernel symbol/type information that
  `dwarf2json` extracted from the CentOS 5 `vmlinux` debug image.

The file vendored here is **bit-identical** to the upstream copy at
acquisition time; SHA-256 in `SHA256SUMS` provides verification. We do
not modify the symbol data.

## Combined Licensing of MemoryHound

This single vendored file is incorporated into a project distributed
under Apache-2.0 (see `LICENSE` at repo root). The combined SPDX
expression is:

```
Apache-2.0 AND GPL-2.0-only AND LicenseRef-VolatilitySoftwareLicense-1.0
```

— each component's terms apply to the corresponding portion of the
distribution. The Apache-2.0 license at the repo root governs MemoryHound
source code; this directory is the only place GPL-2.0 / VSL-1.0 content
appears.

## Refresh

To re-download from upstream and re-verify SHA-256 (idempotent):

```bash
MH_REFRESH_SYMBOLS=1 bash scripts/fetch-isf-symbols.sh
```

To verify only (does not re-download):

```bash
bash scripts/fetch-isf-symbols.sh
# or
shasum -a 256 -c corpus/dfrws-2008-memory/symbols/SHA256SUMS
```

## Regeneration From Source (For Posterity)

If both upstream sources disappear, regenerate from the CentOS 5
kernel-debuginfo RPM (available from the CentOS Vault):

```bash
# 1. Install tooling
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json && go build .

# 2. Acquire the kernel-debuginfo RPM from the CentOS Vault
#    (URL pattern; exact mirror may vary)
RPM_URL="https://vault.centos.org/5.11/os/x86_64/CentOS/kernel-debuginfo-2.6.18-8.1.15.el5.x86_64.rpm"
curl -fsSL -o kernel-debuginfo.rpm "$RPM_URL"

# 3. Extract vmlinux + System.map
rpm2cpio kernel-debuginfo.rpm | cpio -idmv
#   yields ./usr/lib/debug/lib/modules/2.6.18-8.1.15.el5/vmlinux
#   plus ./boot/System.map-2.6.18-8.1.15.el5

# 4. Convert to ISF
./dwarf2json linux \
    --system-map ./boot/System.map-2.6.18-8.1.15.el5 \
    --elf ./usr/lib/debug/lib/modules/2.6.18-8.1.15.el5/vmlinux \
    | xz -9 > 2.6.18-8.1.15.el5_64.json.xz
```

Out-of-scope for the hackathon; documented for posterity.
