#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    // Inputs
    const char *label = "test label";
    const char *seed = "test seed";
    const unsigned char secret[48] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const size_t secret_len = sizeof(secret);

    // Concatenate label + seed
    unsigned char seed_buf[256];
    size_t seed_len = strlen(label) + strlen(seed);
    memcpy(seed_buf, label, strlen(label));
    memcpy(seed_buf + strlen(label), seed, strlen(seed));

    // Output buffer
    unsigned char out[64];

    // Set up KDF context
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "TLS1-PRF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA384", 0),
        OSSL_PARAM_octet_string("secret", secret, secret_len),
        OSSL_PARAM_octet_string("seed", seed_buf, seed_len),
        OSSL_PARAM_END
    };

    if (EVP_KDF_derive(kctx, out, sizeof(out), params) <= 0) {
        fprintf(stderr, "EVP_KDF_derive failed\n");
        EVP_KDF_CTX_free(kctx);
        return 1;
    }

    printf("Derived key material:\n");
    print_hex(out, sizeof(out));

    EVP_KDF_CTX_free(kctx);
    return 0;
}

