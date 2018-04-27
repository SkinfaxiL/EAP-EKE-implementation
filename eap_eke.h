#ifndef EAP_EKE_H__
#define EAP_EKE_H__

#include <gmp.h>
#include <openssl/evp.h>

#include <stdint.h>
#include <sys/types.h>

#define EAP_MAX_LENGTH 65535
#define EAP_EKE_HEADER_SIZE 6

#define EAP_HEADER_REQUEST_CODE 1
#define EAP_HEADER_RESPONSE_CODE 2
#define EAP_HEADER_SECCUESS_CODE 3
#define EAP_HEADER_FAILURE_CODE 4

#define EAP_EKE_HEADER_TYPE 53

#define EAP_EKE_HEADER_ID_EXCHANGE 0x01
#define EAP_EKE_HEADER_COMMIT_EXCHANGE 0x02
#define EAP_EKE_HEADER_CONFIRM_EXCHANGE 0x03
#define EAP_EKE_HEADER_FAILURE_EXCHANGE 0x04

#define EAP_EKE_FAILURE_CODE_NO_ERROR 1
#define EAP_EKE_FAILURE_CODE_PROTOCOL_ERROR 2
#define EAP_EKE_FAILURE_CODE_PASSWORD_NOT_FOUND 3
#define EAP_EKE_FAILURE_CODE_AUTHENTICATION_FAILURE 4
#define EAP_EKE_FAILURE_CODE_AUTHORIZATION_FAILURE 5
#define EAP_EKE_FAILURE_CODE_NO_PROPOSAL_CHOSEN 6

#define EAP_EKE_GROUP_1_PRIME "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC7402" \
        "0BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B57662" \
        "5E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FF" \
        "FFFFFFFFFFFFFF"
#define EAP_EKE_GROUP_1_G 5

struct eap_eke_id_node {
    char *name;
    char *pass;
    struct eap_eke_id_node *next;
};

struct eap_eke_header {
    uint8_t code;
    uint8_t id;
    uint16_t len;
    uint8_t type;
    uint8_t exchange;
};

mpz_t *gen_eap_eke_y(uint8_t group, mpz_t* x);
ssize_t gen_eap_eke_enc_key(uint8_t enc_scheme, uint8_t prg_scheme, const char *user_id, const char *server_id,
        const char *password, uint8_t *buffer);

uint8_t get_eap_packet_id(uint8_t *packet);
void get_eap_eke_proposal(uint8_t *packet, uint8_t *group, uint8_t *enc_scheme,
        uint8_t *prg_scheme, uint8_t *mac_scheme);
ssize_t read_eap_packet(int fd, uint8_t *buffer);

ssize_t create_eap_eke_id_request(uint8_t* buffer, uint8_t group, uint8_t enc_scheme,
        uint8_t prg_scheme, uint8_t mac_scheme, const char *identity, int identity_len);
ssize_t create_eap_eke_id_response(uint8_t* buffer, uint8_t* request, const char *identity, int identity_len);
ssize_t create_eap_eke_commit_request(uint8_t* buffer, uint8_t enc_scheme, uint8_t packet_id, mpz_t *y_s,
        EVP_CIPHER_CTX *cipher_ctx, uint8_t *key);
ssize_t create_eap_eke_commit_response(uint8_t* buffer, uint8_t enc_scheme, uint8_t mac_scheme, uint8_t packet_id,
        mpz_t *y_c, EVP_CIPHER_CTX *cipher_ctx, uint8_t *key,uint8_t *Ke, uint8_t *Ki,uint8_t* Nonce_P);

struct eap_eke_id_node *validate_eap_eke_id_request(int fd, uint8_t *packet, struct eap_eke_id_node *server_list);
struct eap_eke_id_node *validate_eap_eke_id_response(int fd, uint8_t *request, uint8_t *response,
        struct eap_eke_id_node *user_list);
mpz_t *validate_eap_eke_commit_request(uint8_t *packet, uint8_t enc_scheme, EVP_CIPHER_CTX *cipher_ctx, uint8_t *key);

ssize_t prg_plus(uint8_t prg_scheme, uint8_t *key, size_t key_len, uint8_t *data, uint8_t data_len,
        uint8_t *buffer, int expected_len);

mpz_t *validate_eap_eke_commit_response(uint8_t *packet, uint8_t enc_scheme, EVP_CIPHER_CTX *cipher_ctx, uint8_t *key);
uint16_t get_eap_packet_len(uint8_t *packet);
ssize_t create_eap_eke_confirm_request(uint8_t* buffer, uint8_t packet_id, uint8_t* PNonce_PS, ssize_t n_len, uint8_t* Auth );
ssize_t create_eap_eke_confirm_response(uint8_t* buffer, uint8_t packet_id, uint8_t* PNonce_S, ssize_t n_len, uint8_t* Auth );
#endif

