#include "eap_eke.h"

#include "validate.h"
#include "util.h"

#include "PNonce.h"

#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

uint8_t gen_id()
{
    srand(time(0));
    return rand();
}

mpz_t *gen_eap_eke_y(uint8_t group, mpz_t* x)
{
    if (group == 1)
    {
        mpz_t *y = (mpz_t *)malloc(sizeof(mpz_t));
        mpz_t p;
        mpz_t exp;

        mpz_init_set_ui(*y, EAP_EKE_GROUP_1_G);
        validate(mpz_init_set_str(p, EAP_EKE_GROUP_1_PRIME, 16), 1, "[ERROR] Initializing group 1 prime");
        mpz_init(exp);

        gmp_randstate_t r_state;
        gmp_randinit_default(r_state);
        gmp_randseed_ui(r_state, time(0));

        mpz_sub_ui(p, p, 2);
        mpz_urandomm(exp, r_state, p);  // from 0 to p - 1
        mpz_add_ui(exp, exp, 2);
        mpz_add_ui(p, p, 2);
        mpz_powm_sec(*y, *y, exp, p);
        mpz_set(*x,exp);

        gmp_randclear(r_state);
        mpz_clear(exp);
        mpz_clear(p);

        return y;
    }
    else
    {
        validate(-1, 0, "[ERROR] Only group 1 is supported right now");
    }
    return NULL;
}

ssize_t prg(uint8_t prg_scheme, const char *data, int data_len, uint8_t *buffer)
{
    if (prg_scheme == 2)
    {
        uint32_t output_len = 32;
        char key[output_len];
        memset(key, 0, output_len);

        HMAC(EVP_sha256(), key, output_len, (uint8_t *)data, data_len, buffer, &output_len);
        return output_len;
    }
    else
    {
        validate(-1, 0, "[ERROR] Only pseudo-random scheme 2 is supported right now");
    }
    return -1;
}

ssize_t prg_plus(uint8_t prg_scheme, uint8_t *key, size_t key_len, uint8_t *data, uint8_t data_len,
        uint8_t *buffer, int expected_len)
{
    if (prg_scheme == 2)
    {
        uint8_t input[EAP_MAX_LENGTH];
        memset(input, 0, EAP_MAX_LENGTH);
        uint8_t counter = 0x01;
        int input_offset = 64;
        ssize_t input_len = copy_bytes(data, &input[input_offset], data_len);
        input[input_offset + input_len] = counter++;

        ssize_t output_len = 0;
        while (expected_len > 0)
        {
            uint32_t hmac_len;
            HMAC(EVP_sha256(), key, key_len, &input[input_offset], input_len + 1, &buffer[output_len], &hmac_len);

            input_len += copy_bytes(&buffer[output_len], input, hmac_len);
            buffer[input_len] = counter++;
            input_offset = 0;

            output_len += hmac_len;
            expected_len -= hmac_len;
        }
        return output_len;
    }
    else
    {
        validate(-1, 0, "[ERROR] Only pseudo-random scheme 2 is supported right now");
    }
    return -1;
}

ssize_t gen_eap_eke_enc_key(uint8_t enc_scheme, uint8_t prg_scheme, const char *client_id, const char *server_id,
        const char *password, uint8_t *buffer)
{
    if (enc_scheme == 1)
    {
        uint8_t temp[EAP_MAX_LENGTH];
        size_t temp_len = validate(prg(prg_scheme, password, strlen(password), buffer),
                2, "[ERROR] Failed to generate temp");

        uint8_t input[EAP_MAX_LENGTH];
        ssize_t input_len = copy_bytes((uint8_t *)server_id, input, strlen(server_id));
        input_len += copy_bytes((uint8_t *)client_id, &input[input_len], strlen(client_id));

        return validate(prg_plus(prg_scheme, temp, temp_len, input, input_len, buffer, 32),
                2, "[ERROR] Failed to generate key");
    }
    else
    {
        validate(-1, 0, "[ERROR] Only encryption scheme 1 is supported right now");
    }
    return -1;
}

uint8_t get_eap_packet_id(uint8_t *packet)
{
    struct eap_eke_header *header = (struct eap_eke_header *)packet;
    return header->id;
}

uint16_t get_eap_packet_len(uint8_t *packet)
{
    struct eap_eke_header *header = (struct eap_eke_header *)packet;
    return ntohs(header->len);
}

void get_eap_eke_proposal(uint8_t *packet, uint8_t *group, uint8_t *enc_scheme,
        uint8_t *prg_scheme, uint8_t *mac_scheme)
{
    uint8_t *payload = (uint8_t *)(packet + sizeof(struct eap_eke_header));
    *group = payload[2];
    *enc_scheme = payload[3];
    *prg_scheme = payload[4];
    *mac_scheme = payload[5];
}

struct eap_eke_id_node *get_id_node(struct eap_eke_id_node *id_list, char* id, size_t id_len)
{
    while (id_list != NULL) {
        if (strlen(id_list->name) == id_len && strncmp(id_list->name, id, id_len) == 0) {
            break;
        }
        id_list = id_list->next;
    }
    return id_list;
}

ssize_t read_eap_packet(int fd, uint8_t *buffer)
{
    validate(read_n(fd, buffer, EAP_EKE_HEADER_SIZE), 1, "[ERROR] Reading EAP-EKE header failed");

    uint16_t len = get_eap_packet_len(buffer);
    //printf("[INFO] len: %d\n",len );
    validate(read_n(fd, &buffer[EAP_EKE_HEADER_SIZE], len - EAP_EKE_HEADER_SIZE), 1,
            "[ERROR] Reading EAP-EKE packet body failed");

    return len;
}

void print_failure_code(uint32_t failure_code)
{
    switch (failure_code)
    {
        case EAP_EKE_FAILURE_CODE_PROTOCOL_ERROR:
            fprintf(stderr, "[ERROR] Protocol Error!\n");
            break;
        case EAP_EKE_FAILURE_CODE_PASSWORD_NOT_FOUND:
            fprintf(stderr, "[ERROR] Password Not Found!\n");
            break;
        case EAP_EKE_FAILURE_CODE_AUTHENTICATION_FAILURE:
            fprintf(stderr, "[ERROR] Authentication Failure!\n");
            break;
        case EAP_EKE_FAILURE_CODE_AUTHORIZATION_FAILURE:
            fprintf(stderr, "[ERROR] Authorization Failure!\n");
            break;
        case EAP_EKE_FAILURE_CODE_NO_PROPOSAL_CHOSEN:
            fprintf(stderr, "[ERROR] No Proposal Chosen Error!\n");
            break;
        default:
            fprintf(stderr, "[ERROR] Unkown Error: (%d)!\n", failure_code);
            break;
    }
}

void check_failure_code(uint8_t *packet)
{
    struct eap_eke_header *header = (struct eap_eke_header *)packet;
    if (header->exchange == EAP_EKE_HEADER_FAILURE_EXCHANGE)
    {
        uint32_t failure_code = ntohl(*(uint32_t *)&packet[EAP_EKE_HEADER_SIZE]);
        print_failure_code(failure_code);
        exit(1);
    }
}

void send_failure_code(int fd, uint8_t id, uint32_t failure_code)
{
    uint8_t buffer[EAP_MAX_LENGTH];

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_FAILURE_CODE;
    header->id = id;
    header->len = htons(EAP_EKE_HEADER_SIZE + 4);
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_FAILURE_EXCHANGE;

    uint32_t *payload = (uint32_t *)(buffer + sizeof(struct eap_eke_header));
    *payload = htonl(failure_code);

    validate(write(fd, buffer, ntohs(header->len)), 1, "[ERROR] Write Failure Code");
    print_failure_code(failure_code);
    exit(1);
}

ssize_t create_eap_eke_id_request(uint8_t *buffer, uint8_t group, uint8_t enc_scheme,
        uint8_t prg_scheme, uint8_t mac_scheme, const char *identity, int identity_len)
{
    validate_cond(group == 1, 0, "[ERROR] Only group 1 is supported right now");
    validate_cond(enc_scheme == 1, 0, "[ERROR] Only encryption scheme 1 is supported right now");
    validate_cond(prg_scheme == 2, 0, "[ERROR] Only pseudo-random scheme 2 is supported right now");
    validate_cond(mac_scheme == 2, 0, "[ERROR] Only MAC scheme 2 is supported right now");
    validate_cond(identity_len < EAP_MAX_LENGTH - 12 * 8, 0, "[ERROR] Identity is too long: %d chars", identity_len);

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_REQUEST_CODE;
    header->id = gen_id();
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_ID_EXCHANGE;

    uint8_t *payload = (uint8_t *)(buffer + sizeof(struct eap_eke_header));
    int num_proposal = 1;
    payload[0] = num_proposal;
    payload[1] = 0; // Reserved
    payload[2] = group;
    payload[3] = enc_scheme;
    payload[4] = prg_scheme;
    payload[5] = mac_scheme;
    strncpy((char *)&payload[6], identity, identity_len);

    uint16_t len = EAP_EKE_HEADER_SIZE + 2 + num_proposal * 4 + identity_len;
    header->len = htons(len);
    return len;
}

struct eap_eke_id_node *validate_eap_eke_id_request(int fd, uint8_t *packet, struct eap_eke_id_node *server_list)
{
    check_failure_code(packet);

    uint8_t *payload = (uint8_t *)(packet + sizeof(struct eap_eke_header));
    uint8_t num_proposal = payload[0];
    uint8_t group = payload[2];
    uint8_t enc_scheme = payload[3];
    uint8_t prg_scheme = payload[4];
    uint8_t mac_scheme = payload[5];
    if (num_proposal != 1 && group != 1 && enc_scheme != 1 && prg_scheme != 2 && mac_scheme != 2) {
        send_failure_code(fd, get_eap_packet_id(packet), EAP_EKE_FAILURE_CODE_NO_PROPOSAL_CHOSEN);
    }

    struct eap_eke_header *header = (struct eap_eke_header *)packet;
    int identity_len = ntohs(header->len) - EAP_EKE_HEADER_SIZE - 2 - num_proposal * 4;
    struct eap_eke_id_node *server_id = get_id_node(server_list, (char *)&payload[6], identity_len);
    if (server_id == NULL) {
        send_failure_code(fd, get_eap_packet_id(packet), EAP_EKE_FAILURE_CODE_PASSWORD_NOT_FOUND);
    }
    return server_id;
}

ssize_t create_eap_eke_id_response(uint8_t* buffer, uint8_t* request, const char *identity, int identity_len)
{
    validate_cond(identity_len < EAP_MAX_LENGTH - 12 * 8, 0, "[ERROR] Identity is too long: %d chars", identity_len);

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_RESPONSE_CODE;
    header->id = get_eap_packet_id(request);
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_ID_EXCHANGE;

    uint8_t *request_payload = (uint8_t *)(request + sizeof(struct eap_eke_header));
    uint8_t *response_payload = (uint8_t *)(buffer + sizeof(struct eap_eke_header));

    int num_proposal = 1;
    response_payload[0] = num_proposal;
    response_payload[1] = 0; // Reserved
    response_payload[2] = request_payload[2];
    response_payload[3] = request_payload[3];
    response_payload[4] = request_payload[4];
    response_payload[5] = request_payload[5];
    strncpy((char *)&response_payload[6], identity, identity_len);

    uint16_t len = EAP_EKE_HEADER_SIZE + 2 + num_proposal * 4 + identity_len;
    header->len = htons(len);
    return len;
}

struct eap_eke_id_node *validate_eap_eke_id_response(int fd, uint8_t *request, uint8_t *response,
        struct eap_eke_id_node *user_list)
{
    check_failure_code(response);
    if (get_eap_packet_id(request) != get_eap_packet_id(response)) {
        send_failure_code(fd, get_eap_packet_id(request), EAP_EKE_FAILURE_CODE_PROTOCOL_ERROR);
    }

    uint8_t *request_payload = (uint8_t *)(request + sizeof(struct eap_eke_header));
    uint8_t *response_payload = (uint8_t *)(response + sizeof(struct eap_eke_header));

    uint8_t num_proposal = response_payload[0];
    int same_group = request_payload[2] == response_payload[2];
    int same_enc_scheme = request_payload[3] == response_payload[3];
    int same_prg_scheme = request_payload[4] == response_payload[4];
    int same_mac_scheme = request_payload[5] == response_payload[5];
    if (num_proposal != 1 && !same_group && !same_enc_scheme && !same_prg_scheme && !same_mac_scheme) {
        send_failure_code(fd, get_eap_packet_id(request), EAP_EKE_FAILURE_CODE_NO_PROPOSAL_CHOSEN);
    }

    struct eap_eke_header *header = (struct eap_eke_header *)response;
    int identity_len = ntohs(header->len) - EAP_EKE_HEADER_SIZE - 2 - num_proposal * 4;
    struct eap_eke_id_node *user_id = get_id_node(user_list, (char *)&response_payload[6], identity_len);
    if (user_id == NULL) {
        send_failure_code(fd, get_eap_packet_id(request), EAP_EKE_FAILURE_CODE_PASSWORD_NOT_FOUND);
    }
    return user_id;
}

ssize_t create_eap_eke_commit_request(uint8_t* buffer, uint8_t enc_scheme, uint8_t packet_id, mpz_t *y_s,
        EVP_CIPHER_CTX *cipher_ctx, uint8_t *key)
{
    validate_cond(enc_scheme == 1, 0, "[ERROR] Only encryption scheme 1 is supported right now");

    char *plaintext = mpz_get_str(NULL, 16, *y_s);
    size_t payload_len = encrypt_aes128(cipher_ctx, (uint8_t *)plaintext, strlen(plaintext), key,
            &buffer[EAP_EKE_HEADER_SIZE]);

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_RESPONSE_CODE;
    header->id = packet_id;
    header->len = htons(payload_len + EAP_EKE_HEADER_SIZE);
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_COMMIT_EXCHANGE;

    free(plaintext);
    return ntohs(header->len);
}

mpz_t *validate_eap_eke_commit_request(uint8_t *packet, uint8_t enc_scheme, EVP_CIPHER_CTX *cipher_ctx, uint8_t *key)
{
    check_failure_code(packet);
    validate_cond(enc_scheme == 1, 0, "[ERROR] Only encryption scheme 1 is supported right now");
    //printf("%d\n", get_eap_packet_len(packet));

    uint8_t temp[EAP_MAX_LENGTH];
    size_t temp_len = decrypt_aes128(cipher_ctx, &packet[EAP_EKE_HEADER_SIZE],
            get_eap_packet_len(packet) - EAP_EKE_HEADER_SIZE, key, temp);
    temp[temp_len] = '\0';
    //printf(">>>>>>>>>>> encryp size: %d; mpz_t size: %d\n", get_eap_packet_len(packet) - EAP_EKE_HEADER_SIZE, sizeof(mpz_t));
    mpz_t *y = (mpz_t *)malloc(sizeof(mpz_t));
    validate(mpz_init_set_str(*y, (char *)temp, 16), 1, "[ERROR] Initializing y from request");
    return y;
}

ssize_t create_eap_eke_commit_response(uint8_t* buffer, uint8_t enc_scheme, uint8_t mac_scheme, uint8_t packet_id,
        mpz_t *y_c, EVP_CIPHER_CTX *cipher_ctx, uint8_t *key, uint8_t *Ke, uint8_t *Ki, uint8_t* Nonce_P)
{
    validate_cond(enc_scheme == 1, 0, "[ERROR] Only encryption scheme 1 is supported right now");

    char *plaintext = mpz_get_str(NULL, 16, *y_c);
    size_t payload_len = encrypt_aes128(cipher_ctx, (uint8_t *)plaintext, strlen(plaintext), key,
            &buffer[EAP_EKE_HEADER_SIZE]);
    // printf(">>>> y_c encryption length: %zu\n", payload_len);
    // TODO: Add PNonce_P
    // printf("Compute PNonce_P\n");

    ssize_t PNonce_len = Prot(enc_scheme, mac_scheme, Ke, Ki, Nonce_P, NONCE_LEN,
            &buffer[EAP_EKE_HEADER_SIZE + payload_len]);
    // print_hex(&buffer[EAP_EKE_HEADER_SIZE + payload_len], PNonce_len, "[INFO] PNonce_P");
    payload_len += PNonce_len;

    // printf("payload: %zu, PNonce_len: %zu;\n", payload_len, PNonce_len);

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_RESPONSE_CODE;
    header->id = packet_id;
    header->len = htons(payload_len + EAP_EKE_HEADER_SIZE);
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_COMMIT_EXCHANGE;

    free(plaintext);
    return ntohs(header->len);
}

mpz_t *validate_eap_eke_commit_response(uint8_t *packet, uint8_t enc_scheme, EVP_CIPHER_CTX *cipher_ctx,
        uint8_t *key)
{
    check_failure_code(packet);
    validate_cond(enc_scheme == 1, 0, "[ERROR] Only encryption scheme 1 is supported right now");
    // printf(">>>> %d\n", get_eap_packet_len(packet));
    // printf(">>>> y_c encryption length: %d\n", get_eap_packet_len(packet)- PNONCE_LEN - EAP_EKE_HEADER_SIZE);

    uint8_t temp[EAP_MAX_LENGTH];
    size_t temp_len = decrypt_aes128(cipher_ctx, &packet[EAP_EKE_HEADER_SIZE],
            get_eap_packet_len(packet) - EAP_EKE_HEADER_SIZE - PNONCE_LEN, key, temp);
    temp[temp_len] = '\0';

    mpz_t *y = (mpz_t *)malloc(sizeof(mpz_t));
    validate(mpz_init_set_str(*y, (char *)temp, 16), 1, "[ERROR] Initializing y from request");
    return y;
}

ssize_t create_eap_eke_confirm_request(uint8_t *buffer, uint8_t packet_id, uint8_t *PNonce_PS, ssize_t n_len,
        uint8_t *Auth)
{
    uint8_t *payload = buffer + EAP_EKE_HEADER_SIZE;
    memcpy(payload, PNonce_PS, n_len);
    memcpy(payload + n_len, Auth, AUTH_LEN);

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_REQUEST_CODE;
    header->id = packet_id;
    header->len = htons(n_len + AUTH_LEN + EAP_EKE_HEADER_SIZE);
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_CONFIRM_EXCHANGE;

    return ntohs(header->len);
}

ssize_t create_eap_eke_confirm_response(uint8_t* buffer, uint8_t packet_id, uint8_t* PNonce_S, ssize_t n_len,
        uint8_t* Auth)
{
    uint8_t *payload = buffer + EAP_EKE_HEADER_SIZE;
    memcpy(payload, PNonce_S, n_len);
    memcpy(payload + n_len, Auth, AUTH_LEN);
    // printf("======= %zd %d %d\n", n_len, AUTH_LEN, EAP_EKE_HEADER_SIZE);

    struct eap_eke_header *header = (struct eap_eke_header *)buffer;
    header->code = EAP_HEADER_RESPONSE_CODE;
    header->id = packet_id;
    header->len = htons(n_len + AUTH_LEN + EAP_EKE_HEADER_SIZE);
    header->type = EAP_EKE_HEADER_TYPE;
    header->exchange = EAP_EKE_HEADER_CONFIRM_EXCHANGE;

    return ntohs(header->len);
}
