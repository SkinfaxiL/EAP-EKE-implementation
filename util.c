#include "util.h"

#include "validate.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void print_hex_line(const uint8_t *line, int len, int offset)
{
	int i;
	int gap;
	const uint8_t *ch;

	/* offset */
	printf("    %06x   ", offset);

	/* hex */
	ch = line;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = line;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
}

ssize_t copy_bytes(const uint8_t *from, uint8_t *to, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        to[i] = from[i];
    }
    return len;
}

void print_hex(const uint8_t *data, int len, const char* header)
{
    printf("%s:\n", header);

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const uint8_t *ch = data;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_line(ch, len_rem, offset);
			break;
		}
	}
}

ssize_t read_n(int fd, uint8_t *buffer, int n)
{
    int left = n;
    while(left > 0) {
        ssize_t len = read(fd, buffer, left);
        if (len <= 0) return -1;

        left -= len;
        buffer += len;
    }
    return n;
}

ssize_t encrypt_aes128(EVP_CIPHER_CTX *ctx, uint8_t *plaintext, size_t plaintext_len, const uint8_t *key,
        uint8_t *ciphertext)
{
    validate_cond(RAND_bytes(ciphertext, 16), 2, "Server: fail to generate iv");

    validate_cond(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, ciphertext), 2, "[ERROR] EVP_EncryptInit_ex");
    ssize_t ciphertext_len = 16;

    int len;
    validate_cond(EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext, plaintext_len), 2,
            "[ERROR] EVP_EncryptUpdate()");
    ciphertext_len += len;

    validate_cond(EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len), 2, "[ERROR] EVP_EncryptFinal_ex");
    ciphertext_len += len;

    return ciphertext_len;
}

ssize_t decrypt_aes128(EVP_CIPHER_CTX *ctx, uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key,
        uint8_t *plaintext)
{
    uint8_t temp[16];
    copy_bytes(key, temp, 16);

    int len;
    size_t plaintext_len;
    validate_cond(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, temp, ciphertext), 2, "[ERROR] EVP_DecryptInit_ex");

    size_t offset = 16;
    validate_cond(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + offset, ciphertext_len - offset),
            2, "[ERROR] EVP_EncryptUpdate");
    plaintext_len = len;

    validate_cond(EVP_DecryptFinal_ex(ctx, plaintext + len, &len), 2, "[ERROR] EVP_DecryptFinal_ex");
    plaintext_len += len;

    return plaintext_len;
}

int HMAC_verify(uint8_t *hmac, unsigned int hmac_len, uint8_t *data, size_t data_len, const uint8_t *Ki)
{
	uint8_t buffer[65535];
	unsigned int new_hmac_len;
	// print_hex(buffer, 32, "[INFO] buffer!!!");
	HMAC(EVP_sha256(), Ki, KI_LEN, data, data_len, buffer, &new_hmac_len);
	// printf("data len: %zu\n", data_len);
	// print_hex(data, data_len, "[INFO]data!!!");
	// print_hex(Ki, KI_LEN, "[INFO]key!!!");
	// print_hex(buffer, new_hmac_len, "[INFO] buffer!!!");
	// print_hex(hmac, hmac_len, "[INFO] hmac!!!");
	if (new_hmac_len == hmac_len && memcmp(buffer, hmac, hmac_len) == 0){
		printf("[INFO] HMAC verification success!\n");
		return 1;
	} else {
		printf("[INFO] HMAC verification fail!\n");
		return 0;
	}
}

