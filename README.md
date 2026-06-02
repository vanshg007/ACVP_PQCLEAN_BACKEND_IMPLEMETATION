# ML-KEM PQClean backend — implementation walkthrough

**Date:** 2026-05-22
**Outcome:** PASSED — parser response matched NIST's `expectedResults.json` for all 12 test groups (3 parameter sets x 4 functions, 165 test cases) on first verified run with key-check fixes.

## What this is

A from-scratch acvp-parser backend that drives [PQClean](https://github.com/PQClean/PQClean)'s reference (`clean`) ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 implementations against the same ACVP sample vectors used in [`../dryrun_mlkem/DRY_RUN.md`](../dryrun_mlkem/DRY_RUN.md). The earlier dry run validated that the harness can drive an existing backend (OpenSSL 3.6) end to end; this work is the actual handler implementation the project goal called for.

Backend file: `backends/backend_pqclean.c`. Make target: `pqclean`.

## Inputs

| Source                                              | Role                                                 |
| --------------------------------------------------- | ---------------------------------------------------- |
| `parser/parser_ml_kem.h`                            | Defines the 5-callback `struct ml_kem_backend` interface we have to implement |
| `backends/backend_openssl3.c` (lines 5038-5326)     | Reference implementation pattern (cipher dispatch, keygen/encap/decap/checks, constructor registration) |
| `PQClean/crypto_kem/ml-kem-{512,768,1024}/clean/`   | PQClean reference sources, one tree per parameter set |
| `PQClean/common/`                                   | `fips202.c` (SHA-3 / SHAKE) and `randombytes.c` (CryptGenRandom on Windows) |
| `new/{prompt,expectedResults}.json`                 | NIST-supplied ACVP sample vectors (vsId 42, isSample) |

## Step 1: Understand the backend contract

`parser/parser_ml_kem.h` declares one callback struct that the parser invokes against whichever implementation a backend registers via `register_ml_kem_impl()`:

```c
struct ml_kem_backend {
    int (*ml_kem_keygen)(struct ml_kem_keygen_data *, flags_t);
    int (*ml_kem_encapsulation)(struct ml_kem_encapsulation_data *, flags_t);
    int (*ml_kem_decapsulation)(struct ml_kem_decapsulation_data *, flags_t);
    int (*ml_kem_enc_check)(struct ml_kem_enc_check_data *, flags_t);
    int (*ml_kem_dec_check)(struct ml_kem_dec_check_data *, flags_t);
};
```

Three observations from reading the data structs:

1. **Keygen is deterministic.** The parser gives us `d` and `z` (32 bytes each) and expects the same `ek`/`dk` the spec would produce from those exact seeds.
2. **Encap is deterministic.** The parser gives us `msg` (32 bytes) instead of letting us roll our own randomness.
3. The `*_check` callbacks return a verdict in `data->check_success`. They are invoked for the `decapsulationKeyCheck` and `encapsulationKeyCheck` parameter sets, which are pure input-validation tests.

## Step 2: Pick the right PQClean entry points

PQClean's `api.h` only exposes the standard NIST PQClean trio — `crypto_kem_keypair`, `crypto_kem_enc`, `crypto_kem_dec` — and the first two call `randombytes()` internally, which kills determinism. Reading `kem.h` (which is _not_ included from `api.h`) shows two more entry points per variant:

```c
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand    (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
```

The `*_derand` variants take an external coin buffer (`2 * 32 = 64` bytes for keygen, `32` bytes for encap) and are exactly the deterministic primitives ACVP needs.

A friction point: each variant's `params.h` redefines unprefixed macros (`KYBER_K`, `KYBER_ETA1`, etc.) with different values. Including more than one PQClean `kem.h` from a single translation unit would either collide or silently take whichever path resolves first. Since the function symbols themselves are already variant-prefixed (`PQCLEAN_MLKEM{512,768,1024}_CLEAN_*`), the backend just forward-declares them and includes nothing PQClean-internal except `fips202.h` (which has no macro collisions).

## Step 3: Write the backend

`backends/backend_pqclean.c` is structured as:

| Section                            | Purpose                                                       |
| ---------------------------------- | ------------------------------------------------------------- |
| Forward declarations               | One block of three `*_keypair_derand` / `*_enc_derand` / `*_dec` extern declarations per variant |
| `struct pqclean_ml_kem_variant`    | Per-variant dispatch table: name, rank k, all byte sizes, function pointers |
| `pqclean_get_ml_kem_variant()`     | Maps `ACVP_ML_KEM_{512,768,1024}` -> variant table entry      |
| `pqclean_ml_kem_keygen()`          | Concatenate `d || z` into a 64-byte coin buffer, call `keypair_derand`, return `ek`/`dk` |
| `pqclean_ml_kem_encapsulation()`   | Validate lengths, call `enc_derand(ct, ss, ek, msg)`          |
| `pqclean_ml_kem_decapsulation()`   | Validate lengths, call `dec(ss, ct, dk)`. PQClean's `dec` is already constant-time and returns the rejection PRF output for malformed ciphertext, which is what ACVP expects |
| `pqclean_ml_kem_modulus_check()`   | FIPS 203 sec 7.2 / 7.3 modulus check (see Step 5)             |
| `pqclean_ml_kem_pkhash_check()`    | FIPS 203 sec 7.3 H(ek) consistency check (see Step 5)         |
| `pqclean_ml_kem_enc_check()`       | Length check + modulus check on `ek`                          |
| `pqclean_ml_kem_dec_check()`       | Length check + modulus check on embedded `ek` + H(ek) check   |
| Registration                       | `ACVP_DEFINE_CONSTRUCTOR(...)` invoking `register_ml_kem_impl(&pqclean_ml_kem)` |

Cipher dispatch and registration mirror `backend_openssl3.c` exactly; only the per-call logic differs.

## Step 4: Wire it into the build

`backends.mk` gets a new stanza modelled on the OpenSSL one:

```make
ifeq (pqclean,$(firstword $(MAKECMDGOALS)))
    C_SRCS += backends/backend_pqclean.c
    C_SRCS += $(wildcard PQClean/crypto_kem/ml-kem-512/clean/*.c)
    C_SRCS += $(wildcard PQClean/crypto_kem/ml-kem-768/clean/*.c)
    C_SRCS += $(wildcard PQClean/crypto_kem/ml-kem-1024/clean/*.c)
    C_SRCS += PQClean/common/fips202.c
    C_SRCS += PQClean/common/randombytes.c
    INCLUDE_DIRS += PQClean/common
    CFLAGS += -Wno-error -Wno-pedantic -Wno-redundant-decls \
              -Wno-missing-prototypes -Wno-strict-prototypes \
              -Wno-unused-parameter -Wno-sign-compare \
              -Wno-cast-qual -Wno-deprecated-declarations
    ifeq ($(OS),Windows_NT)
        LIBRARIES += advapi32
    endif
endif
```

Three details worth flagging:

- `randombytes.c` is linked even though our backend never calls it, because PQClean's `kem.c` references `randombytes()` from the non-derand wrappers we still inherit by linking the whole `.o`. Easier than maintaining a stub.
- On Windows MinGW, `randombytes.c` uses `CryptAcquireContext` / `CryptGenRandom`, hence `-ladvapi32`.
- The main Makefile compiles everything with `-Werror -Wall -Wextra -pedantic`; PQClean's reference sources predate that policy and trip a handful of warnings. The `-Wno-*` list lets the upstream sources compile unmodified — no in-tree patches required.

The same target name (`pqclean`) is also added to the Makefile's `.PHONY` line and given a `$(NAME)` build rule.

## Step 5: First run uncovers the input-validation gap

Build went through clean on first try. The cryptographic outputs (`c`, `k`) matched bit-for-bit on the first run — the only mismatches were 15 entries in the `decapsulationKeyCheck` groups (tg=7, 9, 11) where our backend returned `testPassed=true` for keys that ACVP expected to be rejected as `false`. All failing cases had the **correct** byte length:

```
tg=7  ML-KEM-512  decapsulationKeyCheck  tc=108  dk_len=1632       expected_pass=False  got_pass=True
tg=9  ML-KEM-768  decapsulationKeyCheck  tc=126  dk_len=2400       expected_pass=False  got_pass=True
tg=11 ML-KEM-1024 decapsulationKeyCheck  tc=146  dk_len=3168       expected_pass=False  got_pass=True
...
```

By contrast every failing case in `encapsulationKeyCheck` (tg=8, 10, 12) had the wrong length and was already being caught.

The cause is that PQClean has no public "is this key well-formed?" entry point. OpenSSL's `EVP_PKEY_fromdata(..., EVP_PKEY_KEYPAIR, ...)` performs the FIPS 203 sec 7.3 checks under the hood, which is why `backend_openssl3.c` gets these tests right by accident. With PQClean we have to do the checks ourselves.

Per FIPS 203 sec 7.2 (encap) and sec 7.3 (decap), validating an ek or a dk that contains an embedded ek requires three checks:

1. **Type Check** — byte length is exactly `384k + 32` for ek or `768k + 96` for dk.
2. **Modulus Check** — when ek is decoded back into 12-bit coefficients (`k` polynomials, 256 coefficients each), every coefficient must be `< q = 3329`. The PQClean encoding packs two 12-bit coefficients into three bytes, little-endian:
   ```
   c0 = b0 | ((b1 & 0x0f) << 8)
   c1 = (b1 >> 4) | (b2 << 4)
   ```
3. **Hash Check** (dk only) — the 32 bytes at offset `768k + 32` inside dk must equal `SHA3-256(ek)` where `ek` is the embedded copy at offset `384k`.

The fix added two helpers (`pqclean_ml_kem_modulus_check`, `pqclean_ml_kem_pkhash_check`) using PQClean's own `sha3_256()` from `common/fips202.h`, and wired them into `pqclean_ml_kem_enc_check` and `pqclean_ml_kem_dec_check`.

## Step 6: Re-run, full pass

```powershell
$env:Path = "C:\Program Files\Git\usr\bin;C:\ProgramData\mingw64\mingw64\bin;" + $env:Path
mingw32-make clean
mingw32-make pqclean

cd dryrun_mlkem_pqclean
..\acvp-parser.exe testvector-request.json testvector-response.json
..\acvp-parser.exe -v -v -e testvector-expected.json testvector-response.json
```

Output of the compare step:

```
[PASSED] compare testvector-expected.json with testvector-response.json
```

The companion `diff.py` script (which does case-insensitive hex comparison — the parser's hex serializer is lowercase, the NIST expected file is uppercase, but the parser's own compare logic is case-insensitive) reports `total mismatched fields: 0`.

## What got tested

All 12 ACVP test groups from `new/prompt.json` (vsId 42) now match `new/expectedResults.json` exactly with the PQClean backend driving the crypto:

| tgId | parameterSet  | function                | testType | n  |
| ---- | ------------- | ----------------------- | -------- | -- |
| 1    | ML-KEM-512    | encapsulation           | AFT      | 25 |
| 2    | ML-KEM-768    | encapsulation           | AFT      | 25 |
| 3    | ML-KEM-1024   | encapsulation           | AFT      | 25 |
| 4    | ML-KEM-512    | decapsulation           | VAL      | 10 |
| 5    | ML-KEM-768    | decapsulation           | VAL      | 10 |
| 6    | ML-KEM-1024   | decapsulation           | VAL      | 10 |
| 7    | ML-KEM-512    | decapsulationKeyCheck   | VAL      | 10 |
| 8    | ML-KEM-512    | encapsulationKeyCheck   | VAL      | 10 |
| 9    | ML-KEM-768    | decapsulationKeyCheck   | VAL      | 10 |
| 10   | ML-KEM-768    | encapsulationKeyCheck   | VAL      | 10 |
| 11   | ML-KEM-1024   | decapsulationKeyCheck   | VAL      | 10 |
| 12   | ML-KEM-1024   | encapsulationKeyCheck   | VAL      | 10 |

165 test cases. Every produced value matches the NIST-supplied expected output.

## Files in this folder

| File                          | Notes                                          |
| ----------------------------- | ---------------------------------------------- |
| `PQCLEAN_BACKEND.md`          | This document                                  |
| `testvector-request.json`     | `../new/prompt.json` wrapped in the ACVP `[version, obj]` array |
| `testvector-expected.json`    | `../new/expectedResults.json` wrapped likewise |
| `testvector-response.json`    | What `acvp-parser.exe` (PQClean build) produced |
| `parser-run.log`              | Log of the parser running the vectors          |
| `parser-compare.log`          | `[PASSED]` line from the `-e` compare run      |
| `diff.py`                     | Case-insensitive per-field diff helper         |
| `inspect.py`                  | Per-tcId breakdown of mismatched `testPassed`  |

## Reproducing

From the repo root:

```powershell
$env:Path = "C:\Program Files\Git\usr\bin;C:\ProgramData\mingw64\mingw64\bin;" + $env:Path
mingw32-make clean
mingw32-make pqclean

cd dryrun_mlkem_pqclean
python -c "import json; ver={'acvVersion':'1.0'}; \
  prompt=json.load(open(r'..\\new\\prompt.json')); \
  json.dump([ver,prompt], open('testvector-request.json','w')); \
  er=json.load(open(r'..\\new\\expectedResults.json')); \
  json.dump([ver,er], open('testvector-expected.json','w'))"

..\acvp-parser.exe testvector-request.json testvector-response.json
..\acvp-parser.exe -e testvector-expected.json testvector-response.json
```

No OpenSSL, conda env, or external library is required — PQClean is fully self-contained. The three Windows-MinGW source patches from the OpenSSL dry run (`Makefile -Wno-unused-function`, two `#undef interface` blocks in `parser_ml_dsa.h` / `parser_slh_dsa.h`) are still in place but unrelated to this backend.

## What this validates and what it doesn't

- Validates that the PQClean ML-KEM reference is bit-identical to FIPS 203 for the published sample vectors, and that `backend_pqclean.c` correctly drives it through every ACVP-defined function and parameter set.
- Validates the FIPS 203 sec 7.2 / 7.3 input-validation checks against vectors that intentionally include malformed keys.
- Does **not** speak to constant-time properties, side-channel resistance, or memory safety beyond what PQClean already documents. PQClean's `clean` profile is the reference for correctness; the `avx2` and `aarch64` profiles (also bundled) would be the choice for performance work and would need their own backend instantiation.
- Does **not** exercise large-scale or randomized vectors — only NIST's sample set. A real CAVP submission would run a full ACVP server-issued vector set against this same binary.
