```
██╗  ██╗███████╗███╗   ███╗    ███████╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗ ██████╗ ██████╗
██║  ██║██╔════╝████╗ ████║    ██╔════╝████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████╗██╔████╔██║    █████╗  ██╔████╔██║██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝
██╔══██║╚════██║██║╚██╔╝██║    ██╔══╝  ██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║███████║██║ ╚═╝ ██║    ███████╗██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝    ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2333-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/hsm-emulator)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-F7A41D?style=flat&logo=zig&logoColor=white)](https://ziglang.org)
[![PKCS#11](https://img.shields.io/badge/PKCS%2311-v2.40-4B7BEC?style=flat)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os.html)
[![Verified with](https://img.shields.io/badge/verified-pkcs11--tool-green?style=flat)](https://github.com/OpenSC/OpenSC)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> A software **Hardware Security Module** that compiles to a real Cryptoki (PKCS#11) shared object. Load it with `pkcs11-tool`, OpenSSL, or any PKCS#11 host the same way you would a real smartcard or HSM — it speaks the C ABI byte-for-byte.

## Why PKCS#11 in Zig

PKCS#11 (Cryptoki) is the C-ABI standard that smartcards, YubiKeys, and cloud HSMs all speak. A conforming module is a `.so` that exports one function — `C_GetFunctionList` — returning a 68-entry table of function pointers in a *fixed canonical order*. Get one struct offset or one pointer slot wrong and the host loads garbage.

That makes it a perfect showcase for Zig's C interop: `extern struct` with natural alignment, `callconv(.c)`, a version script that exports exactly one symbol, and a hand-written ABI that is **machine-checked against the official OASIS headers at build time**.

## What Works Today (M0)

- Loads cleanly under OpenSC `pkcs11-tool` 0.26.1 — enumerates the slot and token (`-L`) and advertises 19 mechanisms (`-M`)
- Exports **only** `C_GetFunctionList` (verified with `objdump -T`)
- The full v2.40 ABI hand-written in `src/ck.zig`: every type, 200+ constants, every struct, and the 68-entry `CK_FUNCTION_LIST` in canonical order
- A build-time cross-check (`zig build test`) that translates the vendored OASIS headers and asserts `@sizeOf` / `@offsetOf` / constant equality **and per-function C-ABI signatures** against `ck.zig` — the spec compliance is a compile-time invariant, not a hope
- General + slot/token entry points implemented for real; session, object, crypto, key-management, and RNG entry points are typed stubs returning `CKR_FUNCTION_NOT_SUPPORTED` until their milestone lands

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd Cybersecurity-Projects/PROJECTS/advanced/hsm-emulator
./install.sh
```

`install.sh` checks for Zig 0.16, OpenSC, and OpenSSL, builds the module in ReleaseSafe, runs the ABI cross-check + smoke test, and confirms `pkcs11-tool` can load it. Then drive it like any real token:

```bash
pkcs11-tool --module zig-out/lib/libhsm.so -L    # list slots and token
pkcs11-tool --module zig-out/lib/libhsm.so -M    # list mechanisms
```

```
Available slots:
Slot 0 (0x0): AngelaMos HSM Emulator Slot 0
  token state:   uninitialized
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see everything. `just spy -L` wraps the module in `pkcs11-spy.so` and logs every Cryptoki call — the fastest way to watch the ABI work.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Architecture

The same three-layer split SoftHSM2 uses: a thin C-ABI façade over typed core state over the store and crypto backends.

```
   PKCS#11 host (pkcs11-tool, OpenSSL, p11-kit)
                      │  C ABI
                      ▼
   ┌───────────────────────────────────────────┐
   │  C_GetFunctionList  (src/main.zig)          │   one exported symbol,
   │  68-entry CK_FUNCTION_LIST                  │   one version script
   └───────────────────────┬─────────────────────┘
                           │
   ┌───────────────────────┴─────────────────────┐
   │  ABI façade   src/ck.zig  +  src/api/*.zig   │   hand-written Cryptoki ABI
   │  general · slot_token · session · object ·   │   + per-call entry points
   │  crypto_ops · keymgmt · random               │
   └───────────────────────┬─────────────────────┘
                           │
   ┌───────────────────────┴─────────────────────┐
   │  core state   src/core/{state,lock}.zig      │   global instance, init args,
   │                                              │   C-boundary-safe locking
   └───────────────────────┬─────────────────────┘
                           │
   ┌───────────────────────┴─────────────────────┐
   │  store + crypto   (built milestone by        │   in-memory → encrypted file
   │  milestone: sessions, objects, AES/EC/RSA)   │   backend at rest
   └───────────────────────────────────────────────┘
```

**Design decisions:** non-RSA crypto is pure-Zig `std.crypto`; RSA links libcrypto (OpenSSL EVP) since `std.crypto` has no public RSA. RNG is sourced from `getrandom(2)` directly (there is no `std.Io` at the C boundary, and `std.crypto.random` was removed in Zig 0.16). The ABI is structured for v2.40 with room to add the v3.0 `C_GetInterface` surface later.

## Build and Test

```bash
zig build               # build the module → zig-out/lib/libhsm.so
zig build test          # ABI cross-check vs OASIS headers + unit tests
zig build smoke         # dlopen the built .so and exercise the ABI as a host would
just ci                 # fmt-check + test + smoke
```

The smoke harness in `examples/smoke.zig` is not a unit test — it `dlopen`s the *actual built shared object* and calls through the function list exactly like an external host, so it catches export and ABI-shape bugs that in-process tests cannot.

## Run in Docker

No Zig or OpenSC on the host? The container builds the module and drives it end-to-end through `pkcs11-tool` — token init, RSA + EC keygen and signing, AES-CBC round-trip — all inside the image.

```bash
just docker-demo        # build the image, then run the full pkcs11-tool demo
```

Or with Docker directly:

```bash
docker build -t angelamos-hsm:latest .
docker run --rm angelamos-hsm:latest
```

A multi-stage build compiles the module in ReleaseSafe in a `debian-slim` builder, then ships only the `.so` plus `opensc` and `libssl3` in a ~96 MB runtime image. The demo exits non-zero if any signature fails to verify.

## Project Structure

```
hsm-emulator/
├── build.zig              # addLibrary(.dynamic), version script, test + smoke steps, translate-c
├── build.zig.zon          # package manifest
├── pkcs11.map             # version script — exports only C_GetFunctionList
├── src/
│   ├── ck.zig             # the hand-written Cryptoki v2.40 ABI (types, constants, structs, list)
│   ├── config.zig         # identity strings, key-size bounds, mechanism list (no magic numbers)
│   ├── util.zig           # comptime helpers (space-padded fixed fields)
│   ├── main.zig           # exported C_GetFunctionList + the wired 68-slot table
│   ├── core/
│   │   ├── state.zig       # global instance, init-args parsing, atomic init flag
│   │   └── lock.zig        # spinlock wrapper (std.Thread.Mutex is gone in 0.16)
│   └── api/
│       ├── general.zig     # C_Initialize / Finalize / GetInfo  (locking template)
│       ├── slot_token.zig  # slot + token + mechanism queries
│       └── session.zig, object.zig, crypto_ops.zig, keymgmt.zig, random.zig
├── tests/abi_test.zig     # @sizeOf/@offsetOf/constant asserts, incl. cross-check vs OASIS
├── examples/smoke.zig     # loads the built .so via dlopen and drives it
└── vendor/pkcs11/         # unmodified OASIS v2.40 headers (build-time cross-check only)
```

## Roadmap

Each milestone ends with a proof from a real external tool — no feature is "done" until `pkcs11-tool` or OpenSSL exercises it.

| Milestone | Scope | Proof |
|-----------|-------|-------|
| **M0** ✅ | Scaffold + hand-written ABI + loadable `.so` | `pkcs11-tool -L/-M`, `objdump -T` |
| **M1** | Sessions + login + PIN (Argon2id, lockout) | `pkcs11-tool --init-token --init-pin --login --change-pin` |
| **M2** | Objects + find (in-memory), `CKA_PRIVATE` gating | `pkcs11-tool -O --read-object` |
| **M3** | RNG + SHA + HMAC + AES-GCM/CBC | `--hash --encrypt --decrypt --generate-random` |
| **M4** | ECDSA P-256/384 + keygen | `--keypairgen EC --sign`, cross-verify with OpenSSL |
| **M5** | RSA via libcrypto (v1.5 / PSS / OAEP) | OpenSSL pkcs11 provider signs through the module |
| **M6** | Encrypted file backend at rest (AES-256-GCM under Argon2id KEK) | persist across restart; tamper → fails closed |
| **M7** | Hardening (secret zeroization, fail-closed) + Docker | — |
| **M8** | Learn modules + mechanism reference + final docs | — |

## License

[AGPL 3.0](LICENSE)
