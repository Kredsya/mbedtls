#include <stdio.h>
#include <stdint.h>

/*
 * Defensive PoC simulator (not a network exploit):
 * shows how using the wrong type domain can skip a TLS 1.2 curve-policy check.
 */

typedef enum {
    MBEDTLS_PK_NONE = 0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
} mbedtls_pk_type_t;

typedef uint16_t psa_key_type_t;

#define MBEDTLS_SSL_VERSION_TLS1_2 0x0303
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 23
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 24

/* Minimal PSA-style encoding used for demonstration. */
#define PSA_KEY_TYPE_CATEGORY_MASK ((psa_key_type_t) 0x7000)
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY ((psa_key_type_t) 0x6001)
#define PSA_KEY_TYPE_IS_ECC(type) \
    ((((psa_key_type_t) (type)) & PSA_KEY_TYPE_CATEGORY_MASK) == \
     (PSA_KEY_TYPE_ECC_PUBLIC_KEY & PSA_KEY_TYPE_CATEGORY_MASK))

typedef struct {
    int tls_version;
    int allowed_curve;
} ssl_context_sim;

typedef struct {
    mbedtls_pk_type_t pk_type;      /* domain: mbedtls_pk_type_t */
    psa_key_type_t psa_key_type;    /* domain: psa_key_type_t */
    int cert_curve;                 /* IANA group id */
} cert_sim;

static int curve_allowed(const ssl_context_sim *ssl, int cert_curve)
{
    return ssl->allowed_curve == cert_curve;
}

/* Mirrors vulnerable gate shape: PSA macro fed by mbedtls_pk_type_t. */
static int verify_cert_vulnerable(const ssl_context_sim *ssl, const cert_sim *cert)
{
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
        PSA_KEY_TYPE_IS_ECC(cert->pk_type)) {
        if (!curve_allowed(ssl, cert->cert_curve)) {
            return -1; /* reject */
        }
    }

    return 0; /* accepted */
}

/* Mirrors fixed gate shape: PSA macro fed by psa_key_type_t. */
static int verify_cert_fixed(const ssl_context_sim *ssl, const cert_sim *cert)
{
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
        PSA_KEY_TYPE_IS_ECC(cert->psa_key_type)) {
        if (!curve_allowed(ssl, cert->cert_curve)) {
            return -1; /* reject */
        }
    }

    return 0; /* accepted */
}

int main(void)
{
    ssl_context_sim ssl = {
        .tls_version = MBEDTLS_SSL_VERSION_TLS1_2,
        .allowed_curve = MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
    };

    cert_sim peer_ecc_cert = {
        .pk_type = MBEDTLS_PK_ECDSA,
        .psa_key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY,
        .cert_curve = MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, /* disallowed */
    };

    int vuln_ret = verify_cert_vulnerable(&ssl, &peer_ecc_cert);
    int fixed_ret = verify_cert_fixed(&ssl, &peer_ecc_cert);

    printf("=== TLS 1.2 ECC curve-policy bypass simulator ===\n");
    printf("Policy: allow only secp256r1, peer cert uses secp384r1\n");
    printf("vulnerable gate result: %s\n", vuln_ret == 0 ? "ACCEPTED (bypass)" : "REJECTED");
    printf("fixed gate result: %s\n", fixed_ret == 0 ? "ACCEPTED" : "REJECTED (expected)");

    return (vuln_ret == 0 && fixed_ret != 0) ? 0 : 1;
}
