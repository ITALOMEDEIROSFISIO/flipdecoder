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
#include <assert.h>

#include "safer.h"
#include "ebk.h"
#include "md5.h"

static void computeMD5key(char *src, char *dest) {
    Ebk ebk;
    unsigned char key[] = "548-4664-826";
    unsigned char tmp[32];
    int i;
    MD5_CTX ctx;
    
    EbkInit(&ebk, key, sizeof(key)-1);
    i = EbkDecodeString(&ebk, src, tmp, sizeof(tmp));
    if(i <= 0) {
        fprintf(stderr, "Failed decoding base64.\n");
        exit(1);
    }
    
    MD5_Init(&ctx);
    MD5_Update(&ctx, tmp, i);
    MD5_Update(&ctx, tmp, i);
    MD5_Final(tmp, &ctx);

    for(i = 0; i < 16; i++) {
        snprintf(dest, 3, "%02x", tmp[i]);
        dest += 2;
    }
}

static void processFile(char *md5key, char *filename) {
    static unsigned char buf[2048*SAFER_BLOCK_LEN];
    static char outname[2048];
    FILE *infile, *outfile;
    char *sep;
    int len;
    Ebk ebk;

    assert(strlen(filename) < sizeof(outname) - 4);
    strncpy(outname, filename, sizeof(outname));
    if((sep = strrchr(outname, '.'))) {
        memmove(sep + 4, sep, strlen(sep)+1);
        memcpy(sep, ".out", 4);
    }
    else {
        strncat(outname, ".out", sizeof(outname)); 
    }

    assert(infile = fopen(filename, "rb"));
    assert(outfile = fopen(outname, "wb"));
    
    EbkInit(&ebk, (unsigned char *)md5key, 32);

    while((len = fread(buf, 1, sizeof(buf), infile))) {
        EbkDecodeBuffer(&ebk, buf, buf, sizeof(buf));
        fwrite(buf, 1, len, outfile);
    }

    fclose(infile);
    fclose(outfile);
}

int main(int argc, char **argv) {
    int i;
    char md5key[33];

    if(argc < 2) {
        fprintf(stderr, "Usage: %s cdmaker_info3 [photo01.jpg ...]\n", argv[0]);
        exit(1);
    }

    Safer_Init_Module();

    computeMD5key(argv[1], md5key);
    printf("MD5 key: %s\n", md5key);

    for(i = 2; i < argc; i++) {
        char *filename = argv[i];
        printf("%s\n", filename);
        processFile(md5key, filename);
    }

    return 0;
}

