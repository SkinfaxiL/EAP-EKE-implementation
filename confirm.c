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
#include <openssl/kdf.h>

ssize_t create_eap_eke_confirm_request(uint8_t* buffer, uint8_t enc_scheme, ){
	uint8_t Nonce_S[16];
	validate_cond(RAND_bytes(Nonce_S, 16), 2, "Server: fail to generate Nonce_S");
	ssize_t len = Prot()
}

ssize_t create_eap_eke_confirm_response(){

}