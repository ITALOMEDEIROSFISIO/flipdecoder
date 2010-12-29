/*
 * Copyright (c) 2010 Paulo Matias
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ebk.h"
#include "ripemd.h"
#include "base64.h"

void EbkInit(Ebk *ebk, unsigned char *key, int len) {
    unsigned char digest[RIPEMD256_DIGESTSIZE];
    struct ripemd_ctx ctx;
    int i;
    
    ripemd256_init(&ctx);
    ripemd_update(&ctx, key, len);
    ripemd_final(&ctx);
    ripemd_digest(&ctx, digest);

    for(i = 0; i < SAFER_BLOCK_LEN; i++)
        ebk->state[i] = 0xff;

    Safer_Expand_Userkey(&digest[0], &digest[8], 10, 1, ebk->key);
    Safer_Encrypt_Block(ebk->state, ebk->key, ebk->state);
}

void EbkDecodeBuffer(Ebk *ebk, unsigned char *src, unsigned char *dest, int len) {
    int i;
    while(len >= SAFER_BLOCK_LEN) {
        unsigned char origsrc[SAFER_BLOCK_LEN];
        memcpy(origsrc, src, SAFER_BLOCK_LEN);
        Safer_Decrypt_Block(origsrc, ebk->key, dest);
        for(i = 0; i < SAFER_BLOCK_LEN; i++)
            dest[i] ^= ebk->state[i];
        for(i = 0; i < SAFER_BLOCK_LEN; i++)
            ebk->state[i] ^= origsrc[i];
        len  -= SAFER_BLOCK_LEN;
        dest += SAFER_BLOCK_LEN;
        src  += SAFER_BLOCK_LEN;
    }
    if(len > 0) {
        unsigned char block[SAFER_BLOCK_LEN];
        Safer_Encrypt_Block(ebk->state, ebk->key, block);
        for(i = 0; i < len; i++)
            dest[i] = src[i] ^ block[i];
        for(i = 0; i < SAFER_BLOCK_LEN; i++)
            ebk->state[i] ^= block[i];
    }
}

int EbkDecodeString(Ebk *ebk, char *src, unsigned char *dest, int destlen) {
    int len = b64_pton(src, dest, destlen);
    EbkDecodeBuffer(ebk, dest, dest, len);
    return len;
}

