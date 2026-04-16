# TLS 1.2 ECC certificate curve check bypass: validation + remediation

## Objective
Validate and remediate the TLS 1.2 ECC certificate curve-check bypass caused by
mixing key-type domains:

- Vulnerable gate used `PSA_KEY_TYPE_IS_ECC(mbedtls_pk_get_type(&chain->pk))`.
- `mbedtls_pk_get_type()` returns `mbedtls_pk_type_t`.
- `PSA_KEY_TYPE_IS_ECC()` expects `psa_key_type_t`.

## Root-cause validation (static)

1. Confirmed the vulnerable gate condition in `library/ssl_tls.c`.
2. Confirmed intended PSA-domain usage in other paths (`mbedtls_pk_get_key_type()`).
3. Confirmed `mbedtls_pk_get_type()` is an mbedtls PK-domain accessor.

## Remediation applied

- Updated TLS 1.2 ECC gate in `library/ssl_tls.c` to use:
  `PSA_KEY_TYPE_IS_ECC(mbedtls_pk_get_key_type(&chain->pk))`

This restores domain-correct ECC detection and ensures curve-policy enforcement
runs for ECC certificates.

## Controlled PoC simulator produced

A **defensive** simulator PoC was added at:

- `programs/test/poc_tls12_ecc_type_mismatch.c`

What it demonstrates:

- Under a vulnerable gate (wrong accessor), a disallowed-curve ECC cert is
  accepted (policy bypass).
- Under a fixed gate (correct accessor), the same cert is rejected.

This is intentionally a local logic simulator (not a weaponized network exploit).

## Local run

```sh
gcc -Wall -Wextra -std=c11 programs/test/poc_tls12_ecc_type_mismatch.c -o /tmp/poc_tls12_ecc_type_mismatch
/tmp/poc_tls12_ecc_type_mismatch
```

Observed output:

```text
=== TLS 1.2 ECC curve-policy bypass simulator ===
Policy: allow only secp256r1, peer cert uses secp384r1
vulnerable gate result: ACCEPTED (bypass)
fixed gate result: REJECTED (expected)
```

## Environment constraints

- Full handshake debug build currently blocked due to missing framework submodule
  content (`framework/CMakeLists.txt` in this checkout).
- `valgrind` and `gdb` are not installed in this environment.
