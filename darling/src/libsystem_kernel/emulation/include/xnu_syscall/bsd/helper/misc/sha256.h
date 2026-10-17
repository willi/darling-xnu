// From Brad Conte's crypto-algorithms (public domain): https://github.com/B-Con/crypto-algorithms
// Its symbols are hidden: libsystem_kernel only uses it to compute code directory hashes.
/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef _DARLING_EMULATION_SHA256_H_
#define _DARLING_EMULATION_SHA256_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
__attribute__((visibility("hidden"))) void sha256_init(SHA256_CTX *ctx);
__attribute__((visibility("hidden"))) void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
__attribute__((visibility("hidden"))) void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

#endif   // SHA256_H
