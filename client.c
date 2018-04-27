#include "eap_eke.h"
#include "validate.h"
#include "util.h"

#include "PNonce.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/rand.h>

struct eap_eke_id_node *SERVER_LIST = NULL;

int sd_server = -1;
mpz_t *y_s = NULL;
mpz_t *y_c = NULL;
EVP_CIPHER_CTX *cipher_ctx = NULL;

void cleanup(void);
void init(void);

int main(int argc, char* argv[])
{
    atexit(cleanup);
    init();

    validate_cond(argc == 4, 0, "Please provide argument [Server IP, Server Port, Username]");
    struct sockaddr_in server_addr = validate_sockaddr(inet_addr(argv[1]), atoi(argv[2]));

    sd_server = validate(socket(AF_INET, SOCK_STREAM, 0), 1, "[ERROR] TCP socket()");
    validate(connect(sd_server, (struct sockaddr *)&server_addr, sizeof(server_addr)), 1, "[ERROR] TCP connect()");
    printf("[INFO] Connect to server: %s:%d\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    uint8_t id_request[EAP_MAX_LENGTH];
    ssize_t id_request_len = read_eap_packet(sd_server, id_request);
    print_hex(id_request, id_request_len, "[INFO] EAP-EKE ID Request");
    struct eap_eke_id_node *server_id = validate_eap_eke_id_request(sd_server, id_request, SERVER_LIST);

    uint8_t group, enc_scheme, prg_scheme, mac_scheme;
    get_eap_eke_proposal(id_request, &group, &enc_scheme, &prg_scheme, &mac_scheme);

    uint8_t id_response[EAP_MAX_LENGTH];
    ssize_t id_response_len = create_eap_eke_id_response(id_response, id_request, argv[3], strlen(argv[3]));
    validate(write(sd_server, id_response, id_response_len), 1, "[ERROR] Write EAP-EKE ID Response");
    print_hex(id_response, id_response_len, "[INFO]  EAP-EKE ID Response");
    printf("[INFO] Server Identity: %s\n", server_id->name);

    uint8_t commit_request[EAP_MAX_LENGTH];
    ssize_t commit_request_len = read_eap_packet(sd_server, commit_request);
    print_hex(commit_request, commit_request_len, "[INFO] EAP-EKE Commit Request");

    uint8_t enc_key[EAP_MAX_LENGTH];
    gen_eap_eke_enc_key(enc_scheme, prg_scheme, argv[3], server_id->name, server_id->pass, enc_key);
    print_hex(enc_key, 32, "[INFO] Encryption Key");
    validate_cond((cipher_ctx = EVP_CIPHER_CTX_new()) != NULL, 2, "[ERROR] EVP_CIPHER_CTX_new()");
    y_s = validate_eap_eke_commit_request(commit_request, enc_scheme, cipher_ctx, enc_key);
    printf("[INFO] Finish validating commit request\n");

    //5.2 client -> server commit response
    uint8_t commit_response[EAP_MAX_LENGTH];
    mpz_t x_c;
    mpz_init(x_c);
    y_c = gen_eap_eke_y(group, &x_c);
    gmp_printf("[INFO] y_s = %Zd\n", *y_s);
    gmp_printf("[INFO] y_c = %Zd\n", *y_c);
    gmp_printf("[INFO] x_c = %Zd\n", x_c);

    uint8_t share_secret[32];
    ssize_t s_len = gen_shared_secret(y_s, &x_c, share_secret);
    print_hex(share_secret, 32 ,"[INFO] Shared Secret");
    //printf("secret length:%d\n", s_len);

    // TODO: Construct commit response and send to the server
    uint8_t Ke[KE_LEN];
    uint8_t Ki[KI_LEN];
    gen_protection_keys(prg_scheme, Ke, Ki, share_secret, 32, server_id->name, argv[3]);
    uint8_t Nonce_P[NONCE_LEN];
    validate_cond(RAND_bytes(Nonce_P, NONCE_LEN), 2, "Client: fail to generate Nonce_P");
    print_hex(Nonce_P, NONCE_LEN, "[INFO] Nonce_P");
    ssize_t commit_response_len = create_eap_eke_commit_response(commit_response, enc_scheme, mac_scheme,
            get_eap_packet_id(commit_request), y_c, cipher_ctx, enc_key, Ke, Ki, Nonce_P);
    validate(write(sd_server, commit_response, commit_response_len), 1, "[ERROR] Write EAP-EKE ID Response");
    print_hex(commit_response, commit_response_len, "[INFO] EAP-EKE Commit Response");

    print_hex(Ke, KE_LEN, "[INFO] Ke");
    print_hex(Ki, KI_LEN, "[INFO] Ki");

    //5.3 server->client validate confirm request
    uint8_t confirm_request[EAP_MAX_LENGTH];
    uint8_t Nonce_PS[NONCE_LEN * 2];
    ssize_t confirm_request_len = read_eap_packet(sd_server, confirm_request);
    print_hex(confirm_request, confirm_request_len, "[INFO] EAP-EKE Confirm Request");

    // uint8_t* cipher = confirm_request + EAP_EKE_HEADER_SIZE;
    // printf("%d\n", IV_LEN+NONCE_LEN*3);
    // print_hex(cipher, 96, "[INFO] PNonce_PS");
    //bug: de_Prot HMAC verify
    de_Prot(enc_scheme, mac_scheme, cipher_ctx, Ke, Ki, confirm_request + EAP_EKE_HEADER_SIZE, 64, Nonce_PS);
    print_hex(Nonce_PS, NONCE_LEN * 2, "[INFO] Nonce_PS");
    uint8_t* Nonce_S = &Nonce_PS[NONCE_LEN];

    uint8_t ka_seed[1024];
    uint8_t ka[KA_LEN];
    ssize_t ka_seed_len = 0;
    memcpy(ka_seed, "EAP-EKE Ka", strlen("EAP-EKE Ka"));
    ka_seed_len += strlen("EAP-EKE Ka");
    memcpy(ka_seed+ka_seed_len, server_id->name, strlen(server_id->name));
    ka_seed_len += strlen(server_id->name);
    memcpy(ka_seed+ka_seed_len, argv[3], strlen(argv[3]));
    ka_seed_len += strlen(argv[3]);
    ka_seed_len += copy_bytes(Nonce_PS, ka_seed + ka_seed_len, NONCE_LEN * 2);
    get_auth_key(prg_scheme,share_secret, SEC_LEN,ka_seed,ka_seed_len, ka);
    print_hex(ka, KA_LEN, "[INFO] Ka");

    uint8_t auth_seed[EAP_MAX_LENGTH];
    ssize_t auth_seed_len = 0;
    memcpy(auth_seed, "EAP-EKE server", strlen("EAP-EKE server"));
    auth_seed_len += strlen("EAP-EKE server");
    memcpy(auth_seed + auth_seed_len, id_request, id_request_len);
    auth_seed_len += id_request_len;
    memcpy(auth_seed + auth_seed_len, id_response, id_response_len);
    auth_seed_len += id_response_len;
    memcpy(auth_seed + auth_seed_len, commit_request, commit_request_len);
    auth_seed_len += commit_request_len;
    memcpy(auth_seed + auth_seed_len, commit_response, commit_response_len);
    auth_seed_len += commit_response_len;

    uint8_t Auth_S[AUTH_LEN];
    ssize_t Auth_S_len = Auth(prg_scheme, ka, auth_seed, auth_seed_len, Auth_S);
    printf("[INFO] Auth_S length: %zd\n", Auth_S_len);
    print_hex(Auth_S, Auth_S_len, "[INFO] Auth_S");

    if(!memcmp(Auth_S, confirm_request + IV_LEN+NONCE_LEN*3 + HMAC_LEN, AUTH_LEN)){
        validate(-1, 0, "Confirm Request Authentication fail");
    }
    printf("[INFO] Confirm Request Authentication success!\n");

    //5.4 client->server confirtm response
    uint8_t PNonce_S[2048];
    ssize_t PNonce_len = Prot(enc_scheme, mac_scheme, Ke, Ki, Nonce_S, NONCE_LEN, PNonce_S);
    // printf("PNonce_len %zu\n", PNonce_len);
    // print_hex(PNonce_S, PNonce_len, "[INFO] PNonce_S");

    memset(auth_seed, 0, EAP_MAX_LENGTH);
    auth_seed_len = 0;
    memcpy(auth_seed, "EAP-EKE peer", strlen("EAP-EKE peer"));
    auth_seed_len += strlen("EAP-EKE peer");
    memcpy(auth_seed + auth_seed_len, id_request, id_request_len);
    auth_seed_len += id_request_len;
    memcpy(auth_seed + auth_seed_len, id_response, id_response_len);
    auth_seed_len += id_response_len;
    memcpy(auth_seed + auth_seed_len, commit_request, commit_request_len);
    auth_seed_len += commit_request_len;
    memcpy(auth_seed + auth_seed_len, commit_response, commit_response_len);
    auth_seed_len += commit_response_len;
    uint8_t Auth_P[AUTH_LEN];
    ssize_t Auth_P_len = Auth(prg_scheme, ka, auth_seed, auth_seed_len, Auth_P);
    // printf("[INFO] Auth_P length: %zd\n", Auth_P_len);
    print_hex(Auth_P, Auth_P_len, "[INFO] Auth_P");

    uint8_t confirm_response[EAP_MAX_LENGTH];
    ssize_t confirm_response_len = create_eap_eke_confirm_response(confirm_response,
            get_eap_packet_id(confirm_request), PNonce_S, PNonce_len, Auth_P);
    // printf("[INFO] confirm_response_len: %zd\n", confirm_response_len);
    validate(write(sd_server, confirm_response, confirm_response_len), 1, "[ERROR] Write EAP-EKE Confirm Response");
    print_hex(confirm_request, confirm_request_len, "[INFO] EAP-EKE Confirm Response");

    uint8_t MSK [MSK_LEN*2];
    uint8_t key_seed [EAP_MAX_LENGTH];
    ssize_t key_seed_len = 0;
    memcpy(key_seed, "EAP-EKE Exported Keys", strlen("EAP-EKE Exported Keys"));
    key_seed_len +=  strlen("EAP-EKE Exported Keys");
    memcpy(key_seed + key_seed_len, server_id->name, strlen(server_id->name));
    key_seed_len +=  strlen(server_id->name);
    memcpy(key_seed + key_seed_len, argv[3], strlen(argv[3]));
    key_seed_len += strlen(argv[3]);
    memcpy(key_seed + key_seed_len, Nonce_P, NONCE_LEN);
    key_seed_len += NONCE_LEN;
    memcpy(key_seed + key_seed_len, Nonce_S, NONCE_LEN);
    key_seed_len += NONCE_LEN;

    prg_plus(prg_scheme, share_secret, s_len, key_seed, key_seed_len, MSK, MSK_LEN * 2);
    print_hex(MSK, MSK_LEN * 2, "[INFO] Following bytes can be used as shared temporary key");

    mpz_clear(x_c);
    return 0;
}

void cleanup(void)
{
    if (sd_server != -1) close(sd_server);
    if (y_s != NULL) { mpz_clear(*y_s); free(y_s); }
    if (y_c != NULL) { mpz_clear(*y_c); free(y_c); }
    if (cipher_ctx != NULL) EVP_CIPHER_CTX_free(cipher_ctx);

    while (SERVER_LIST != NULL) {
        free(SERVER_LIST->name);
        struct eap_eke_id_node *temp = SERVER_LIST;
        SERVER_LIST = SERVER_LIST->next;
        free(temp);
    }

    fprintf(stderr, "Shutting Down...\n");
}

void init(void)
{
    SERVER_LIST = (struct eap_eke_id_node *)malloc(sizeof(struct eap_eke_id_node));

    char server1[] = "CS528_Server";
    char password1[] = "CS528_Password";
    SERVER_LIST->name = (char *)malloc(strlen(server1) + 1);
    SERVER_LIST->pass = (char *)malloc(strlen(password1) + 1);
    strcpy(SERVER_LIST->name, server1);
    strcpy(SERVER_LIST->pass, password1);
    SERVER_LIST->next = NULL;
}

