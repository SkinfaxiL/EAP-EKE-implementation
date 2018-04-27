#ifndef UTIL_H__
#define UTIL_H__

#include <openssl/evp.h>

#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#define KE_LEN 16
#define KI_LEN 32
#define KA_LEN 32
#define MSK_LEN 64
#define EMSK_LEN 64
#define NONCE_LEN 16
#define PNONCE_LEN 80
#define HMAC_LEN 32
#define IV_LEN 16
#define ENC_LEN 32
#define SEC_LEN 32
#define AUTH_LEN 32

ssize_t copy_bytes(const uint8_t *from, uint8_t *to, size_t len);
void print_hex(const uint8_t *data, int len, const char* header);
ssize_t read_n(int fd, uint8_t *buffer, int n);

ssize_t encrypt_aes128(EVP_CIPHER_CTX *ctx, uint8_t *plaintext, size_t plaintext_len, const uint8_t *key,
        uint8_t *ciphertext);
ssize_t decrypt_aes128(EVP_CIPHER_CTX *ctx, uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key,
        uint8_t *plaintext);
int HMAC_verify(uint8_t* hmac, unsigned int hmac_len, uint8_t* data, size_t data_len, const uint8_t* key);

#endif

