#ifndef HEADER_SM3_H
#define HEADER_SM3_H

#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64

#include <sys/types.h>
#include <stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
int StringToHex(const char *str, unsigned char *out, unsigned int *outlen);

typedef struct {
	uint32_t digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
} sm3_ctx_t;


typedef struct {
	sm3_ctx_t sm3_ctx;
	unsigned char key[64];

} sm3_hmac_ctx_t;

int sm3_init(sm3_ctx_t *ctx);
int sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
int sm3_final(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
void sm3(const unsigned char *data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif
#endif

