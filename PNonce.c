#include "eap_eke.h"
#include "validate.h"
#include "util.h"
#include "PNonce.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>



/*
Ke | Ki = prf+(sharedSercret, "EAP-EKE KEYS" | DS_S | DS_P)

generate Ke, Ki, with length e_len, i_len.
    Ke: key for encryption
    Ki: key for check integrity
    share_secret: key for PRF funtion
    e_len, i_len, secret_len, seed_len: all in bytes
*/
int gen_protection_keys(uint8_t prg_scheme, uint8_t* Ke, uint8_t* Ki, uint8_t* share_secret,
                    size_t secret_len, const char *server_id, const char *client_id){
    //uint8_t prg_scheme = 2;  // Pseudo-Random function with SHA-256
    uint8_t seed[EAP_MAX_LENGTH];
    memset(seed, 0, EAP_MAX_LENGTH);
    int seed_len = 0;
    // printf("====== %s\n", server_id);
    // printf("====== %s\n", client_id);
    memcpy(seed, "EAP-EKE Keys", strlen("EAP-EKE Keys"));
    seed_len += strlen("EAP-EKE Keys");
    memcpy(seed + seed_len, server_id, strlen(server_id));
    seed_len += strlen(server_id);
    memcpy(seed + seed_len, client_id, strlen(client_id));
    seed_len += strlen(client_id);
    // printf("====== %s\n", seed);

    uint8_t buffer[EAP_MAX_LENGTH];
    // print_hex(share_secret,32,">>>>> share_secret!!!!");
    validate(prg_plus(prg_scheme, share_secret, 32, seed, seed_len, buffer, KE_LEN + KI_LEN),
            2, "[ERROR] Failed to generate KE key");
    // print_hex(buffer,64,"buffer!!!!");
    memcpy(Ke, buffer, KE_LEN);
    memcpy(Ki, buffer + KE_LEN, KI_LEN);
    return 1;
}

int gen_shared_secret(mpz_t* y, mpz_t* x, uint8_t* share_secret){
    uint8_t key[32];
    memset(key, 0, 32);
    mpz_t tmp, p;
    mpz_init(tmp);
    validate(mpz_init_set_str(p, EAP_EKE_GROUP_1_PRIME, 16), 1, "[ERROR] Initializing group 1 prime");
    mpz_powm_sec(tmp, *y, *x, p);
    //gmp_printf("[INFO] tmp = %Zd\n", tmp);
    //gmp_printf("[INFO] p = %Zd\n", p);
    //print_hex(key,32,"key");
    uint32_t output_len = 32;
    char *plaintext = mpz_get_str(NULL, 16, tmp);
    HMAC(EVP_sha256(), key, 32, (uint8_t *)plaintext, sizeof(mpz_t), share_secret, &output_len);

    free(plaintext);
    return output_len;
}

/*
Encrypt Nouce, and use HMAC to protect it:

*/
int Prot(uint8_t enc_scheme, uint8_t mac_scheme, uint8_t* Ke, uint8_t* Ki, uint8_t* Nouce, size_t N_len,  uint8_t* PNonce)
{
    if (enc_scheme == 1 && mac_scheme == 2)
    {
        validate_cond(N_len % 16 == 0, 0, "[ERROR] Nouce length must be multiple of 16");

        //encrypt
        size_t len = 0;
        EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
        size_t encry_len = encrypt_aes128(cipher_ctx, Nouce, N_len, Ke, PNonce);
        len += encry_len;
        // print_hex(PNonce, encry_len, ">>>>> PNonce");

        //HMAC
        unsigned int hmac_len;
        HMAC(EVP_sha256(), Ki, KI_LEN, PNonce, encry_len, PNonce + encry_len, &hmac_len);
        len += hmac_len;
        // printf("~~~~~ %zu, %zu, %d\n", len, encry_len, hmac_len);
        // print_hex(PNonce + encry_len, hmac_len, ">>>>> HMAC");
        // print_hex(Ki, KI_LEN, ">>>>> Ki");

        EVP_CIPHER_CTX_free(cipher_ctx);
        return len;
    }
    else
    {
        validate(-1, 0, "[ERROR] Only encryption scheme 1(aes128-cbc) and MAC scheme 2(HMAC-sha256) is supported right now");
    }
    return -1;
}

int de_Prot(uint8_t enc_scheme, uint8_t mac_scheme, EVP_CIPHER_CTX *cipher_ctx, const uint8_t *Ke, const uint8_t *Ki,
        uint8_t *cipher, ssize_t c_len, uint8_t *Nonce)
{
    if (enc_scheme == 1 && mac_scheme == 2)
    {
        //!!!!! BUG !!!!

        validate_cond(HMAC_verify(cipher + c_len, HMAC_LEN, cipher, c_len, Ki), 0, "[ERROR] HMAC fail!!");
        return decrypt_aes128(cipher_ctx, cipher, c_len, Ke, Nonce);
    }
    else
    {
        validate(-1, 0, "[ERROR] Only encryption scheme 1(aes128-cbc) and MAC scheme 2(HMAC-sha256) is supported right now");
    }
    return -1;
}

int get_auth_key(uint8_t prg_scheme, uint8_t *share_secret, size_t secret_len, uint8_t *seed, size_t seed_len,
        uint8_t *Ka)
{
    if (prg_scheme == 2)
    {
        return validate(prg_plus(prg_scheme, share_secret, secret_len, seed, seed_len, Ka, KA_LEN),
                2,"[ERROR] Failed to generate KA key");
    }
    else
    {
        validate(-1, 0, "[ERROR] Only pseudo-random scheme 2 is supported right now");
    }
    return -1;

}

/*
Sign the preceding messages:

*/
int Auth(uint8_t prg_scheme, uint8_t *Ka, uint8_t *seed, size_t s_len, uint8_t *out)
{
    if (prg_scheme == 2)
    {
        uint32_t output_len = 32;
        HMAC(EVP_sha256(), Ka, KA_LEN, seed, s_len, out, &output_len);
        return output_len;
    }
    else
    {
        validate(-1, 0, "[ERROR] Only pseudo-random scheme 2 is supported right now");
    }
    return -1;
}

/*
section 5.5 generate MSK and EMSK
*/



