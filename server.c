#include "eap_eke.h"
#include "validate.h"
#include "util.h"

#include "PNonce.h"

#include <gmp.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/rand.h>

#define MAX_CONN 5

char SERVER_IDENTITY[] = "CS528_Server";
struct eap_eke_id_node *USER_LIST = NULL;

int sd_server = -1;
int sd_client = -1;
mpz_t *y_s = NULL;
mpz_t *y_c = NULL;
EVP_CIPHER_CTX *cipher_ctx = NULL;

void cleanup(void);
void init(void);

int main(int argc, char* argv[])
{
    atexit(cleanup);
    init();

    validate_cond(argc == 2, 0, "[ERROR] Please provide argument [Server Port]");
    struct sockaddr_in server_addr = validate_sockaddr(INADDR_ANY, atoi(argv[1]));

    sd_server = validate(socket(AF_INET, SOCK_STREAM, 0), 1, "[ERROR] TCP socket()");
    validate(bind(sd_server, (struct sockaddr *)&server_addr, sizeof(server_addr)), 1, "[ERROR] TCP bind()");
    validate(listen(sd_server, MAX_CONN), 1, "[ERROR] TCP listen() error");

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    sd_client = validate(accept(sd_server, (struct sockaddr *)&client_addr, &client_len), 1, "[ERROR] TCP accept()");
    printf("[INFO] Connect to client: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    uint8_t id_request[EAP_MAX_LENGTH];
    uint8_t group = 1;       // 1024-bit prime number with generator 5
    uint8_t enc_scheme = 1;  // 128-bit AES with CBC mode
    uint8_t prg_scheme = 2;  // Pseudo-Random function with SHA-256
    uint8_t mac_scheme = 2;  // MAC with SHA-256
    ssize_t id_request_len = validate(create_eap_eke_id_request(id_request, group, enc_scheme, prg_scheme,
            mac_scheme, SERVER_IDENTITY, strlen(SERVER_IDENTITY)), 0, "[ERROR] Create EAP-EKE ID Request");
    validate(write(sd_client, id_request, id_request_len), 1, "[ERROR] Write EAP-EKE ID Request");
    uint8_t packet_id = get_eap_packet_id(id_request);
    print_hex(id_request, id_request_len, "[INFO] EAP-EKE ID Request");

    uint8_t id_response[EAP_MAX_LENGTH];
    ssize_t id_response_len = read_eap_packet(sd_client, id_response);
    print_hex(id_response, id_response_len, "[INFO] EAP-EKE ID Response");
    struct eap_eke_id_node *user_id = validate_eap_eke_id_response(sd_client, id_request, id_response, USER_LIST);
    printf("[INFO] Client Identity: %s, Initial Packet Id: %d\n", user_id->name, packet_id);

    uint8_t enc_key[EAP_MAX_LENGTH];
    gen_eap_eke_enc_key(enc_scheme, prg_scheme, user_id->name, SERVER_IDENTITY, user_id->pass, enc_key);
    print_hex(enc_key, 32, "[INFO] Encryption Key");

    uint8_t commit_request[EAP_MAX_LENGTH];
    mpz_t x_s;
    mpz_init(x_s);
    validate_cond((cipher_ctx = EVP_CIPHER_CTX_new()) != NULL, 2, "[ERROR] EVP_CIPHER_CTX_new()");
    y_s = gen_eap_eke_y(group,&x_s);
    ssize_t commit_request_len = create_eap_eke_commit_request(commit_request, enc_scheme, ++packet_id, y_s,
            cipher_ctx, enc_key);
    validate(write(sd_client, commit_request, commit_request_len), 1, "[ERROR] Write EAP-EKE Commit Request");
    print_hex(commit_request, commit_request_len, "[INFO] EAP-EKE Commit Request");

    //5.2 validate commit response
    uint8_t commit_response[EAP_MAX_LENGTH];
    ssize_t commit_response_len = read_eap_packet(sd_client, commit_response);
    y_c = validate_eap_eke_commit_response(commit_response, enc_scheme, cipher_ctx, enc_key);
    print_hex(commit_response, commit_response_len, "[INFO] EAP-EKE Commit Response");

    gmp_printf("[INFO] y_s = %Zd\n", *y_s);
    gmp_printf("[INFO] y_c = %Zd\n", *y_c);
    gmp_printf("[INFO] x_c = %Zd\n", x_s);

    uint8_t share_secret[EAP_MAX_LENGTH];
    ssize_t s_len = gen_shared_secret(y_c, &x_s, share_secret);
    print_hex(share_secret, 32, "[INFO] Shared Secret");
    // printf("secret length: %zd\n", s_len);

    uint8_t Ke[KE_LEN];
    uint8_t Ki[KI_LEN];
    gen_protection_keys(prg_scheme, Ke, Ki, share_secret, 32, SERVER_IDENTITY, user_id->name);
    uint8_t Nonce_P[NONCE_LEN];
    uint8_t* cipher = commit_response + get_eap_packet_len(commit_response) - PNONCE_LEN;
    de_Prot(enc_scheme, mac_scheme, cipher_ctx, Ke, Ki, cipher, IV_LEN + NONCE_LEN * 2, Nonce_P);
    print_hex(Ke, KE_LEN, "[INFO] Ke");
    print_hex(Ki, KI_LEN, "[INFO] Ki");
    print_hex(Nonce_P, NONCE_LEN, "[INFO] Nonce_P");
    // ??? where touch Ki ??
    // works if re-initialize Ki
    gen_protection_keys(prg_scheme, Ke, Ki, share_secret, 32, SERVER_IDENTITY, user_id->name);
    // print_hex(Ki, KI_LEN, ">>>>> Ki02");

    //5.3 server->client confirm request
    uint8_t Nonce_PS[NONCE_LEN*2];
    memcpy(Nonce_PS, Nonce_P, NONCE_LEN);
    validate_cond(RAND_bytes(Nonce_PS + NONCE_LEN, NONCE_LEN), 2, "Client: fail to generate Nonce_P");
    print_hex(Nonce_PS + NONCE_LEN, NONCE_LEN, "[INFO] Nonce_S");
    uint8_t PNonce_PS[2048];
    // print_hex(Ki, KI_LEN, ">>>>> Ki01");
    ssize_t PNonce_len = Prot(enc_scheme, mac_scheme, Ke, Ki, Nonce_PS, NONCE_LEN * 2, PNonce_PS);
    // printf("PNonce_len %zu\n", PNonce_len);
    print_hex(PNonce_PS, PNonce_len, "[INFO] PNonce_PS");

    uint8_t ka_seed[1024];
    uint8_t ka[KA_LEN];
    ssize_t ka_seed_len = 0;
    memcpy(ka_seed, "EAP-EKE Ka", strlen("EAP-EKE Ka"));
    ka_seed_len += strlen("EAP-EKE Ka");
    memcpy(ka_seed+ka_seed_len, SERVER_IDENTITY, strlen(SERVER_IDENTITY));
    ka_seed_len += strlen(SERVER_IDENTITY);
    memcpy(ka_seed+ka_seed_len,user_id->name, strlen(user_id->name));
    ka_seed_len += strlen(user_id->name);
    ka_seed_len += copy_bytes(Nonce_PS, ka_seed + ka_seed_len, NONCE_LEN * 2);
    get_auth_key(prg_scheme, share_secret, SEC_LEN, ka_seed, ka_seed_len, ka);
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
    // printf("[INFO] Auth_S length: %zd\n", Auth_S_len);
    print_hex(Auth_S, Auth_S_len, "[INFO] Auth_S");

    uint8_t confirm_request[EAP_MAX_LENGTH];
    ssize_t confirm_request_len = create_eap_eke_confirm_request(confirm_request, ++packet_id, PNonce_PS,
            PNonce_len, Auth_S);
    validate(write(sd_client, confirm_request, confirm_request_len), 1, "[ERROR] Write EAP-EKE Commit Request");
    print_hex(confirm_request, confirm_request_len, "[INFO] EAP-EKE Confirm Request");

    // 5.4 client->server validate confirtm response
    uint8_t confirm_response[EAP_MAX_LENGTH];
    uint8_t Nonce_S[NONCE_LEN];
    ssize_t confirm_response_len = read_eap_packet(sd_client, confirm_response);
    print_hex(confirm_response, confirm_response_len, "[INFO] EAP-EKE Confirm Response");

    cipher = confirm_response + EAP_EKE_HEADER_SIZE;
    // printf("%d\n", IV_LEN+NONCE_LEN*2);
    // print_hex(cipher, IV_LEN+NONCE_LEN*2, "[INFO] PNonce_S");
    de_Prot(enc_scheme, mac_scheme, cipher_ctx, Ke, Ki, cipher, IV_LEN + NONCE_LEN * 2, Nonce_S);
    validate_cond(memcmp(Nonce_PS + NONCE_LEN, Nonce_S, NONCE_LEN) == 0, 0, "[ERROR] Nonce_S Does Not Match");
    // print_hex(Nonce_S, NONCE_LEN, "[INFO] Nonce_S");

    // auth_seed[EAP_MAX_LENGTH];
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
    // print_hex(Auth_P, Auth_P_len, "[INFO] Auth_P");

    if (Auth_P_len == AUTH_LEN && !memcmp(Auth_P, confirm_response + IV_LEN+NONCE_LEN*2 + HMAC_LEN, AUTH_LEN)) {
        validate(-1, 0, "Confirm Response Authentication fail");
    }
    printf("[INFO] Confirm Response Authentication success!\n");

    //5.5 MSK and EMSK

    uint8_t MSK[MSK_LEN * 2];
    uint8_t key_seed [EAP_MAX_LENGTH];
    ssize_t key_seed_len = 0;
    memcpy(key_seed, "EAP-EKE Exported Keys", strlen("EAP-EKE Exported Keys"));
    key_seed_len +=  strlen("EAP-EKE Exported Keys");
    memcpy(key_seed + key_seed_len, SERVER_IDENTITY, strlen(SERVER_IDENTITY));
    key_seed_len +=  strlen(SERVER_IDENTITY);
    memcpy(key_seed + key_seed_len, user_id->name, strlen(user_id->name));
    key_seed_len += strlen(user_id->name);
    memcpy(key_seed + key_seed_len, Nonce_P, NONCE_LEN);
    key_seed_len += NONCE_LEN;
    memcpy(key_seed + key_seed_len, Nonce_S, NONCE_LEN);
    key_seed_len += NONCE_LEN;

    prg_plus(prg_scheme, share_secret, s_len, key_seed, key_seed_len, MSK, MSK_LEN * 2);
    print_hex(MSK, MSK_LEN * 2, "[INFO] Following bytes can be used as shared temporary key");

    mpz_clear(x_s);
    return 0;
}

void cleanup(void)
{
    if (sd_server != -1) close(sd_server);
    if (sd_client != -1) close(sd_client);
    if (y_s != NULL) { mpz_clear(*y_s); free(y_s); }
    if (y_c != NULL) { mpz_clear(*y_c); free(y_c); }
    if (cipher_ctx != NULL) EVP_CIPHER_CTX_free(cipher_ctx);

    while (USER_LIST != NULL) {
        free(USER_LIST->name);
        struct eap_eke_id_node *temp = USER_LIST;
        USER_LIST = USER_LIST->next;
        free(temp);
    }

    fprintf(stderr, "Shutting Down...\n");
}

void init(void)
{
    USER_LIST = (struct eap_eke_id_node *)malloc(sizeof(struct eap_eke_id_node));

    char user1[] = "CS528_User";
    char password1[] = "CS528_Password";
    USER_LIST->name = (char *)malloc(strlen(user1) + 1);
    USER_LIST->pass = (char *)malloc(strlen(password1) + 1);
    strcpy(USER_LIST->name, user1);
    strcpy(USER_LIST->pass, password1);
    USER_LIST->next = NULL;
}

