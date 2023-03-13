/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __HVB_CRYPTO_H_
#define __HVB_CRYPTO_H_

#include <stdint.h>

#define HASH_OK     0
#define VERIFY_OK   0x5A5A

#define BLK_WORD_SIZE_SHA256 16
#define BLK_BYTE_SIZE_SHA256 (BLK_WORD_SIZE_SHA256 * sizeof(uint32_t))

#define IV_WORD_SIZE_SHA256  8
#define IV_BYTE_SIZE_SHA256  (IV_WORD_SIZE_SHA256 * sizeof(uint32_t))

#define HVB_SHA256_DIGEST_BYTES 32
#define HVB_SHA512_DIGEST_BYTES 64
/* sha512 is 64 bytes */
#define HVB_HASH_MAX_BYTES      64

struct hvb_rsa_pubkey {
    uint32_t width;
    uint32_t e;
    uint8_t *pn;
    uint32_t nlen;
    uint8_t *p_rr;
    uint32_t rlen;
    uint64_t n_n0_i;
};

enum hash_alg_type {
    HASH_ALG_SHA256,
};

struct hash_ctx_t {
    uint32_t alg_type;

    uint32_t buf_len;
    uint32_t total_len;

    uint32_t iv[IV_BYTE_SIZE_SHA256];

    uint8_t  blk_buf[BLK_BYTE_SIZE_SHA256];
};

int hash_ctx_init(struct hash_ctx_t *hash_ctx, enum hash_alg_type);

int hash_calc_update(struct hash_ctx_t *hash_ctx, const void *msg, uint32_t msg_len);

int hash_calc_do_final(struct hash_ctx_t *hash_ctx, const void *msg, uint32_t msg_len, uint8_t *out, uint32_t out_len);

int hash_sha256_single(const void *msg, uint32_t msg_len, uint8_t *out, uint32_t out_len);

/*
* Use the key provided in the |pkey| to verify the correctness
* of the RSA |psign| with the length of |signlen| against an
* expected |pdigest| of length |digestlen|.
*
* The data in |pkey| must match the format defined in |hvb_rsa_pubkey|.
*
* Return VERIFY_OK if verification success, error code otherwise.
*/
int hvb_rsa_verify_pss(const struct hvb_rsa_pubkey *pkey, const uint8_t *pdigest,
                       uint32_t digestlen, uint8_t *psign,
                       uint32_t signlen, uint32_t saltlen);

#endif