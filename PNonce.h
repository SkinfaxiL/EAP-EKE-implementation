#ifndef PNONCE_H__
#define PNONCE_H__

#include <gmp.h>
#include <openssl/evp.h>

#include <stdint.h>
#include <sys/types.h>




int gen_protection_keys(uint8_t prg_scheme, uint8_t* Ke, uint8_t* Ki, uint8_t* share_secret, 
					size_t secret_len, const char *server_id, const char *client_id);

int gen_shared_secret(mpz_t* y, mpz_t* x, uint8_t* share_secret);

int Prot(uint8_t enc_scheme, uint8_t mac_scheme, uint8_t* Ke, uint8_t* Ki, uint8_t* Nouce, 
		size_t N_len,  uint8_t* PNonce);

int de_Prot(uint8_t enc_scheme, uint8_t mac_scheme, EVP_CIPHER_CTX *cipher_ctx, const uint8_t* Ke, const uint8_t* Ki, uint8_t* cipher, ssize_t c_len, uint8_t* Nonce);

int get_auth_key(uint8_t prg_scheme, uint8_t* share_secret, size_t secret_len, 
				uint8_t* seed, size_t seed_len, uint8_t* Ka );

int Auth(uint8_t prg_scheme, uint8_t* Ka, uint8_t* seed, size_t s_len, uint8_t* out);

#endif