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
#include <stddef.h>
#include <hvb_sysdeps.h>
#include "hvb_crypto.h"
#include "hvb_hash_sha256.h"

#ifndef htobe32
#define htobe32(value)                                                                          \
    ((((value)&0x000000FF) << 24) | (((value)&0x0000FF00) << 8) | (((value)&0x00FF0000) >> 8) | \
        (((value)&0xFF000000) >> 24))
#endif

#define word2byte(w) ((w) * sizeof(uint32_t))
#define PAD_BLK_WORD_SIZE_SHA256 (BLK_WORD_SIZE_SHA256 * 2)
#define PAD_BLK_BYTE_SIZE_SHA256 WOR2BYTE(PAD_BLK_WORD_SIZE_SHA256)
#define PAD_INFO_BYTE_LEN_SHA256 8

#define shr(x, n) (((uint32_t)(x)) >> (n))
#define rotr(x, n) (shr(x, n) | (((uint32_t)(x)) << (32 - (n))))

#define sigma_0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define sigma_1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define sigma_2(x) (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3))
#define sigma_3(x) (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10))

#define maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))

static const uint32_t const_key[] = {
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
};


static uint32_t sha256_iv_init[IV_WORD_SIZE_SHA256] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static inline uint32_t bigend_read_word(const uint8_t *data)
{
    uint32_t res;

    res = data[0];
    res = (res << 8) | data[1];
    res = (res << 8) | data[2];
    res = (res << 8) | data[3];

    return res;
}

static inline uint32_t w_schedule(uint32_t w[64], uint32_t t)
{
    return sigma_3(w[t - 2]) + w[t - 7] + sigma_2(w[t - 15]) + w[t - 16];
}

static inline void rotate_regs(uint32_t regs[8])
{
    uint32_t backup;
    backup = regs[6];
    regs[6] = regs[5];
    regs[5] = regs[4];
    regs[4] = regs[3];
    regs[3] = regs[2];
    regs[2] = regs[1];
    regs[1] = regs[0];
    regs[0] = regs[7];
    regs[7] = backup;
}

static void sha256_block_calc(uint32_t regs[8], const uint8_t *data)
{
    uint32_t t1;
    uint32_t w[64];
    uint32_t t;

    for (t = 0; t < 64; t++, data += 4) {
        w[t] = t < 16 ? bigend_read_word(data) : w_schedule(w, t);
        t1 = regs[7] + sigma_1(regs[4]) + ch(regs[4], regs[5], regs[6]) + const_key[t] + w[t];
        regs[3] += t1;
        regs[7] = sigma_0(regs[0]) + maj(regs[0], regs[1], regs[2]) + t1;

        rotate_regs(regs);
    }
}

int sha256_data_blk_update(uint32_t *iv, const void *msg, uint64_t len);

__attribute__((weak)) int sha256_data_blk_update(uint32_t *iv, const void *msg, uint64_t len)
{
    uint32_t regs[8];
    const uint8_t *pdata = msg;
    uint64_t i;
    uint32_t j;

    for (i = 0; i < len / 64; i++, pdata += 64) {
        for (j = 0; j < 8; j++) {
            regs[j] = iv[j];
        }

        sha256_block_calc(regs, pdata);

        for (j = 0; j < 8; j++) {
            iv[j] += regs[j];
        }
    }
    return 0;
}

static void hash_sha256_pad_update(uint32_t *iv, const void *left_msg, uint64_t left_len, uint64_t total_bit_len)
{
    uint32_t pad_word_len;
    uint32_t sha256_pad[PAD_BLK_WORD_SIZE_SHA256];
    uint8_t *pad_ptr = NULL;
    uint32_t fill_zero_len;

    if (left_len != 0) {
        hvb_memcpy(sha256_pad, left_msg, (uint32_t)left_len);
    }

    pad_ptr = (uint8_t *)sha256_pad;
    pad_ptr[left_len] = 0x80;  // padding 0x80
    left_len++;

    if (left_len + PAD_INFO_BYTE_LEN_SHA256 <= BLK_BYTE_SIZE_SHA256) {
        pad_word_len = BLK_WORD_SIZE_SHA256;
    } else {
        pad_word_len = PAD_BLK_WORD_SIZE_SHA256;
    }

    fill_zero_len = word2byte(pad_word_len) - (uint32_t)left_len - PAD_INFO_BYTE_LEN_SHA256;
    hvb_memset(pad_ptr + left_len, 0, fill_zero_len);

    sha256_pad[pad_word_len - 1] = htobe32((uint32_t)total_bit_len);
    total_bit_len = total_bit_len >> 32;
    sha256_pad[pad_word_len - 2] = htobe32((uint32_t)total_bit_len);

    sha256_data_blk_update(iv, sha256_pad, word2byte(pad_word_len));
}

static int hash_sha256_output_iv(uint32_t *iv, uint8_t *out, uint32_t out_len)
{
    if (out_len < IV_BYTE_SIZE_SHA256) {
        return HASH_ERR_OUTBUF_NO_ENOUGH;
    }

    for (int i = 0; i < IV_WORD_SIZE_SHA256; i++) {
        iv[i] = htobe32(iv[i]);
    }

    hvb_memcpy(out, iv, IV_BYTE_SIZE_SHA256);

    return HASH_OK;
}

int hash_sha256_single(const void *msg, uint32_t msg_len, uint8_t *out, uint32_t out_len)
{
    uint64_t data_size;
    uint64_t total_bit_len;
    uint32_t iv[IV_WORD_SIZE_SHA256];

    total_bit_len = (uint64_t)msg_len * 8;  // 8bit per byte
    if (total_bit_len < msg_len) {
        return HASH_ERR_TOTAL_LEN;
    }

    hvb_memcpy(iv, sha256_iv_init, sizeof(sha256_iv_init));

    data_size = (msg_len / BLK_BYTE_SIZE_SHA256) * BLK_BYTE_SIZE_SHA256;

    if (data_size > 0) {
        sha256_data_blk_update(iv, msg, data_size);
    }

    hash_sha256_pad_update(iv, (uint8_t *)msg + data_size, msg_len - data_size, total_bit_len);

    return hash_sha256_output_iv(iv, out, out_len);
}

static uint32_t hash_alg_get_blklen(enum hash_alg_type alg_type)
{
    switch (alg_type) {
        case HASH_ALG_SHA256:
            return BLK_BYTE_SIZE_SHA256;
        default:
            return 0;
    }
    return 0;
}


int hash_ctx_init(struct hash_ctx_t *hash_ctx, enum hash_alg_type alg_type)
{
    if (alg_type != HASH_ALG_SHA256) {
        return HASH_ERR_ALG_NO_SUPPORT;
    }

    if (hash_ctx == NULL) {
        return HASH_ERR_PARAM_NULL;
    }

    hash_ctx->alg_type  = (uint32_t)alg_type;
    hash_ctx->buf_len   = 0;
    hash_ctx->total_len = 0;

    (void)hvb_memcpy(hash_ctx->iv, sha256_iv_init, sizeof(sha256_iv_init));

    return HASH_OK;
}

int hash_calc_update(struct hash_ctx_t *hash_ctx, const void *msg, uint32_t msg_len)
{
    uint32_t left_len;
    uint32_t blk_len;
    uint32_t calc_len;

    if (hash_ctx == NULL) {
        return HASH_ERR_PARAM_NULL;
    }

    blk_len = hash_alg_get_blklen(hash_ctx->alg_type);
    if (blk_len == 0) {
        return HASH_ERR_ALG_NO_SUPPORT;
    }

    if (hash_ctx->buf_len >= blk_len) {
        return HASH_ERR_BUF_LEN;
    }

    hash_ctx->total_len = hash_ctx->total_len + msg_len;

    left_len = blk_len - hash_ctx->buf_len;

    if (hash_ctx->buf_len != 0 && msg_len >= left_len) {
        hvb_memcpy(hash_ctx->blk_buf + hash_ctx->buf_len, msg, left_len);
        sha256_data_blk_update(hash_ctx->iv, hash_ctx->blk_buf, blk_len);

        hash_ctx->buf_len = 0;

        msg_len = msg_len - left_len;
        msg = (uint8_t *)msg + left_len;
    }

    if (msg_len >= blk_len) {
        calc_len = msg_len / blk_len * blk_len;
        sha256_data_blk_update(hash_ctx->iv, msg, calc_len);

        msg_len = msg_len - calc_len;
        msg = (uint8_t *)msg + calc_len;
    }

    if (msg_len != 0) {
        hvb_memcpy(hash_ctx->blk_buf + hash_ctx->buf_len, msg, msg_len);
        hash_ctx->buf_len = hash_ctx->buf_len + msg_len;
    }

    return HASH_OK;
}

int hash_calc_do_final(struct hash_ctx_t *hash_ctx, const void *msg, uint32_t msg_len, uint8_t *out, uint32_t out_len)
{
    uint64_t total_bit_len;
    int ret;

    ret = hash_calc_update(hash_ctx, msg, msg_len);
    if (ret != HASH_OK) {
        return ret;
    }

    total_bit_len = hash_ctx->total_len * 8;
    if (total_bit_len <= hash_ctx->total_len) {
        return HASH_ERR_TOTAL_LEN;
    }

    hash_sha256_pad_update(hash_ctx->iv, hash_ctx->blk_buf, hash_ctx->buf_len, total_bit_len);

    return hash_sha256_output_iv(hash_ctx->iv, out, out_len);
}
