/*
 * Copyright 2014 mkimid
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_blake.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"


static void jackpothash_debug(void *state, const void *input) {
    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    static unsigned char pblank[1];

    uint32_t hash[16];

    int ii;
    unsigned char * ptr = (unsigned char *)input;

    printf("Input Hash : ");
    for (ii = 0; ii < 128; ii++) {
        printf("%.2x", ptr[ii]);
    }
    printf("\n");

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 80);
    sph_keccak512_close(&ctx_keccak, hash);

    ptr = (unsigned char *)(&hash[0]);

    printf("After keccak : ");
    for (ii = 0; ii < 64; ii++) {
        printf("%.2x", ptr[ii]);
    }
    printf("\n");

    unsigned int round;
    for (round = 0; round < 3; round++) {
        if (hash[0] & 0x01) {
           sph_groestl512_init(&ctx_groestl);
           sph_groestl512 (&ctx_groestl, (&hash), 64);
           sph_groestl512_close(&ctx_groestl, (&hash));
        }
        else {
           sph_skein512_init(&ctx_skein);
           sph_skein512 (&ctx_skein, (&hash), 64);
           sph_skein512_close(&ctx_skein, (&hash));
        }
        if (hash[0] & 0x01) {
           sph_blake512_init(&ctx_blake);
           sph_blake512 (&ctx_blake, (&hash), 64);
           sph_blake512_close(&ctx_blake, (&hash));
        }
        else {
           sph_jh512_init(&ctx_jh);
           sph_jh512 (&ctx_jh, (&hash), 64);
           sph_jh512_close(&ctx_jh, (&hash));
        }
        unsigned char * ptr = (unsigned char *)(&hash[0]);
        int ii;
        printf("round %d : ", round);
        for (ii = 0; ii < 64; ii++) {
            printf("%.2x", (unsigned char)ptr[ii]);
        }
        printf("\n");
    }

	memcpy(state, hash, 32);
}

static void jackpothash(void *state, const void *input) {

    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

    uint32_t hash[16];

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 80);
    sph_keccak512_close(&ctx_keccak, (&hash));

    unsigned int round;
    for (round = 0; round < 3; round++) {
        if (hash[0] & 0x01) {
           sph_groestl512_init(&ctx_groestl);
           sph_groestl512 (&ctx_groestl, (&hash), 64);
           sph_groestl512_close(&ctx_groestl, (&hash));
        }
        else {
           sph_skein512_init(&ctx_skein);
           sph_skein512 (&ctx_skein, (&hash), 64);
           sph_skein512_close(&ctx_skein, (&hash));
        }
        if (hash[0] & 0x01) {
           sph_blake512_init(&ctx_blake);
           sph_blake512 (&ctx_blake, (&hash), 64);
           sph_blake512_close(&ctx_blake, (&hash));
        }
        else {
           sph_jh512_init(&ctx_jh);
           sph_jh512 (&ctx_jh, (&hash), 64);
           sph_jh512_close(&ctx_jh, (&hash));
        }
    }

	memcpy(state, hash, 32);
}

int scanhash_jackpot(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done) {
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t target = ptarget[7];
	uint32_t hash[8] __attribute__((aligned(32)));
	uint32_t data[32];
	int i;
	for (i = 0; i < 32; i++) {
		be32enc(&data[i], ((uint32_t*)pdata)[i]);
	};
	if (target <= 0xFFFF) {
       do {
          pdata[19] = ++n;
          be32enc(&data[19], n);
          jackpothash(hash, &data);
          if (hash[7] <= target)  {
             if (fulltest(hash, ptarget)) {
                *hashes_done = n - first_nonce + 1;
                if (opt_hashdebug) {
                   printf(" Found nonce = %.8x \n", n);
                   jackpothash_debug (hash, &data);
                }
                return true;
             }
          }
       } while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else {
	   do {
		  pdata[19] = ++n;
	  	  be32enc(&data[19], n);
		  jackpothash(hash, &data);
		  if (fulltest(hash, ptarget)) {
			  *hashes_done = n - first_nonce + 1;
			  return true;
		  }
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
   *hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}