#!/usr/bin/env bash
set -eu

file="library/ssl_tls.c"

if rg -n "PSA_KEY_TYPE_IS_ECC\(mbedtls_pk_get_type\(&chain->pk\)\)" "$file" >/dev/null; then
    echo "FAIL: vulnerable gate still present in $file"
    exit 1
fi

if ! rg -n "PSA_KEY_TYPE_IS_ECC\(mbedtls_pk_get_key_type\(&chain->pk\)\)" "$file" >/dev/null; then
    echo "FAIL: fixed gate not found in $file"
    exit 1
fi

echo "PASS: TLS 1.2 ECC curve gate uses mbedtls_pk_get_key_type()"
