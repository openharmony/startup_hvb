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
#ifndef __HVB_SM3_H__
#define __HVB_SM3_H__

#include "hvb_sm3.h"
#include "hvb_gm_common.h"
#include "hvb_sysdeps.h"
#include "hvb_util.h"
#include <stdio.h>
#include <stdlib.h>

#define SM3_PRECAL_W_NUMS   16

static const uint32_t const_t[] = {
    0x79cc4519,
    0xf3988a32,
    0xe7311465,
    0xce6228cb,
    0x9cc45197,
    0x3988a32f,
    0x7311465e,
    0xe6228cbc,
    0xcc451979,
    0x988a32f3,
    0x311465e7,
    0x6228cbce,
    0xc451979c,
    0x88a32f39,
    0x11465e73,
    0x228cbce6,
    0x9d8a7a87,
    0x3b14f50f,
    0x7629ea1e,
    0xec53d43c,
    0xd8a7a879,
    0xb14f50f3,
    0x629ea1e7,
    0xc53d43ce,
    0x8a7a879d,
    0x14f50f3b,
    0x29ea1e76,
    0x53d43cec,
    0xa7a879d8,
    0x4f50f3b1,
    0x9ea1e762,
    0x3d43cec5,
    0x7a879d8a,
    0xf50f3b14,
    0xea1e7629,
    0xd43cec53,
    0xa879d8a7,
    0x50f3b14f,
    0xa1e7629e,
    0x43cec53d,
    0x879d8a7a,
    0x0f3b14f5,
    0x1e7629ea,
    0x3cec53d4,
    0x79d8a7a8,
    0xf3b14f50,
    0xe7629ea1,
    0xcec53d43,
    0x9d8a7a87,
    0x3b14f50f,
    0x7629ea1e,
    0xec53d43c,
    0xd8a7a879,
    0xb14f50f3,
    0x629ea1e7,
    0xc53d43ce,
    0x8a7a879d,
    0x14f50f3b,
    0x29ea1e76,
    0x53d43cec,
    0xa7a879d8,
    0x4f50f3b1,
    0x9ea1e762,
    0x3d43cec5,
};

static uint32_t sm3_iv_init[SM3_IV_WORD_SIZE] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E };

/* x is 32bit */
#define rotl(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define p0(x) ((x) ^ rotl((x), 9) ^ rotl((x), 17))
#define p1(x) ((x) ^ rotl((x), 15) ^ rotl((x), 23))
#define ff0(x, y, z) ((x) ^ (y) ^ (z))
#define ff2(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define gg0(x, y, z) ((x) ^ (y) ^ (z))
#define gg1(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define cal_w(w1, w2, w3, w4, w5) \
    (p1((w1) ^ (w2) ^ rotl((w3), 15)) ^ rotl((w4), 7) ^ (w5))

static uint32_t bigend_read_word(const uint8_t *data)
{
    uint32_t res;

    res = data[0];
    res = (res << 8) | data[1];
    res = (res << 8) | data[2];
    res = (res << 8) | data[3];

    return res;
}

#define sm3_round(A, B, C, D, E, F, G, H, T, FF, GG, Wj, Wi) \
    do {                                                     \
        uint32_t a12 = rotl((A), 12);                        \
        uint32_t ss1 = rotl(a12 + (E) + (T), 7);             \
        uint32_t ss2 = ss1 ^ a12;                            \
        uint32_t tt1 = FF((A), (B), (C)) + (D) + ss2 + (Wi); \
        uint32_t tt2 = GG((E), (F), (G)) + (H) + ss1 + (Wj); \
        (B) = rotl((B), 9);                                  \
        (D) = p0(tt2);                                           \
        (F) = rotl((F), 19);                                 \
        (H) = tt1;                                       \
    } while (0)

#define sm3_round_0_15(A, B, C, D, E, F, G, H, T, Wj, Wi) \
    sm3_round(A, B, C, D, E, F, G, H, T, ff0, gg0, Wj, Wi)

#define sm3_round_16_63(A, B, C, D, E, F, G, H, T, Wj, Wi) \
    sm3_round(A, B, C, D, E, F, G, H, T, ff2, gg1, Wj, Wi)

static void sm3_block_calc(uint32_t regs[8], const uint8_t *data)
{
    uint32_t w[SM3_PRECAL_W_NUMS];
    uint32_t i;

    /* pre store w */
    for (i = 0; i < SM3_PRECAL_W_NUMS; i++, data += 4)
        w[i] = bigend_read_word(data);

    sm3_round_0_15(regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
                const_t[0], w[0], w[0] ^ w[4]);
    sm3_round_0_15(regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6],
                const_t[1], w[1], w[1] ^ w[5]);
    sm3_round_0_15(regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5],
                const_t[2], w[2], w[2] ^ w[6]);
    sm3_round_0_15(regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4],
                const_t[3], w[3], w[3] ^ w[7]);
    sm3_round_0_15(regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3],
                const_t[4], w[4], w[4] ^ w[8]);
    sm3_round_0_15(regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2],
                const_t[5], w[5], w[5] ^ w[9]);
    sm3_round_0_15(regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1],
                const_t[6], w[6], w[6] ^ w[10]);
    sm3_round_0_15(regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0],
                const_t[7], w[7], w[7] ^ w[11]);
    sm3_round_0_15(regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
                const_t[8], w[8], w[8] ^ w[12]);
    sm3_round_0_15(regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6],
                const_t[9], w[9], w[9] ^ w[13]);
    sm3_round_0_15(regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5],
                const_t[10], w[10], w[10] ^ w[14]);
    sm3_round_0_15(regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4],
                const_t[11], w[11], w[11] ^ w[15]);
    w[0] = cal_w(w[0], w[7], w[13], w[3], w[10]);
    sm3_round_0_15(regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3],
                const_t[12], w[12], w[12] ^ w[0]);
    w[1] = cal_w(w[1], w[8], w[14], w[4], w[11]);
    sm3_round_0_15(regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2],
                const_t[13], w[13], w[13] ^ w[1]);
    w[2] = cal_w(w[2], w[9], w[15], w[5], w[12]);
    sm3_round_0_15(regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1],
                const_t[14], w[14], w[14] ^ w[2]);
    w[3] = cal_w(w[3], w[10], w[0], w[6], w[13]);
    sm3_round_0_15(regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0],
                const_t[15], w[15], w[15] ^ w[3]);

    for (i = 1; i < 4; i++) {
        w[4]  = cal_w(w[4],  w[11], w[1], w[7],  w[14]);
        sm3_round_16_63(regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
                const_t[i * 16 + 0], w[0], w[0] ^ w[4]);
        w[5]  = cal_w(w[5],  w[12], w[2], w[8],  w[15]);
        sm3_round_16_63(regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6],
                const_t[i * 16 + 1], w[1], w[1] ^ w[5]);
        w[6]  = cal_w(w[6],  w[13], w[3], w[9],  w[0]);
        sm3_round_16_63(regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5],
                const_t[i * 16 + 2], w[2], w[2] ^ w[6]);
        w[7]  = cal_w(w[7],  w[14], w[4], w[10], w[1]);
        sm3_round_16_63(regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4],
                const_t[i * 16 + 3], w[3], w[3] ^ w[7]);
        w[8]  = cal_w(w[8],  w[15], w[5], w[11], w[2]);
        sm3_round_16_63(regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3],
                const_t[i * 16 + 4], w[4], w[4] ^ w[8]);
        w[9]  = cal_w(w[9],  w[0], w[6], w[12], w[3]);
        sm3_round_16_63(regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2],
                const_t[i * 16 + 5], w[5], w[5] ^ w[9]);
        w[10] = cal_w(w[10], w[1], w[7], w[13], w[4]);
        sm3_round_16_63(regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1],
                const_t[i * 16 + 6], w[6], w[6] ^ w[10]);
        w[11] = cal_w(w[11], w[2], w[8], w[14], w[5]);
        sm3_round_16_63(regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0],
                const_t[i * 16 + 7], w[7], w[7] ^ w[11]);
        w[12] = cal_w(w[12], w[3], w[9], w[15], w[6]);
        sm3_round_16_63(regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
                const_t[i * 16 + 8], w[8], w[8] ^ w[12]);
        w[13] = cal_w(w[13], w[4], w[10], w[0], w[7]);
        sm3_round_16_63(regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6],
                const_t[i * 16 + 9], w[9], w[9] ^ w[13]);
        w[14] = cal_w(w[14], w[5], w[11], w[1], w[8]);
        sm3_round_16_63(regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4], regs[5],
                const_t[i * 16 + 10], w[10], w[10] ^ w[14]);
        w[15] = cal_w(w[15], w[6], w[12], w[2], w[9]);
        sm3_round_16_63(regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3], regs[4],
                const_t[i * 16 + 11], w[11], w[11] ^ w[15]);
        w[0] = cal_w(w[0], w[7], w[13], w[3], w[10]);
        sm3_round_16_63(regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2], regs[3],
                const_t[i * 16 + 12], w[12], w[12] ^ w[0]);
        w[1] = cal_w(w[1], w[8], w[14], w[4], w[11]);
        sm3_round_16_63(regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1], regs[2],
                const_t[i * 16 + 13], w[13], w[13] ^ w[1]);
        w[2] = cal_w(w[2], w[9], w[15], w[5], w[12]);
        sm3_round_16_63(regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0], regs[1],
                const_t[i * 16 + 14], w[14], w[14] ^ w[2]);
        w[3] = cal_w(w[3], w[10], w[0], w[6], w[13]);
        sm3_round_16_63(regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[0],
                const_t[i * 16 + 15], w[15], w[15] ^ w[3]);
    }
}

static void sm3_data_blk_update(uint32_t *iv, const void *msg, uint32_t len)
{
    uint32_t regs[8];
    const uint8_t *pdata = msg;
    uint32_t i;
    uint32_t j;

    for (i = 0; i < len / 64; i++, pdata += 64) {
        for (j = 0; j < 8; j++)
            regs[j] = iv[j];

        sm3_block_calc(regs, pdata);

        for (j = 0; j < 8; j++)
            iv[j] ^= regs[j];
    }
}

int hvb_sm3_init(struct sm3_ctx_t *hash_ctx)
{
    if (hvb_check(hash_ctx == NULL))
        return SM3_POINTER_NULL;

    hash_ctx->buf_len   = 0;
    hash_ctx->total_len = 0;

    if (hvb_check(hvb_memcpy_s(hash_ctx->iv, sizeof(hash_ctx->iv), sm3_iv_init, sizeof(sm3_iv_init)) != 0))
        return SM3_MEMORY_ERR;

    return SM3_OK;
}

int hvb_sm3_update(struct sm3_ctx_t *hash_ctx, const void *msg, uint32_t msg_len)
{
    uint32_t left_len;
    uint32_t calc_len;
    uint8_t *msg_tmp = (uint8_t *)msg;

    if (hvb_check(msg == NULL || hash_ctx == NULL))
        return SM3_POINTER_NULL;

    if (hvb_check(msg_len == 0))
        return SM3_MSG_LEN_ERR;

    if (hvb_check(hash_ctx->buf_len >= SM3_BLK_BYTE_SIZE))
        return SM3_BUF_LEN_ERR;

    hash_ctx->total_len += msg_len;
    if (hash_ctx->total_len < msg_len)
        return SM3_OVER_MAX_LEN;

    left_len = SM3_BLK_BYTE_SIZE - hash_ctx->buf_len;

    if (hash_ctx->buf_len != 0 && msg_len >= left_len) {
        if (hvb_check(hvb_memcpy_s(hash_ctx->blk_buf + hash_ctx->buf_len, sizeof(hash_ctx->blk_buf) - sizeof(hash_ctx->buf_len),
                                   msg_tmp, left_len) != 0))
            return SM3_MEMORY_ERR;
        sm3_data_blk_update(hash_ctx->iv, hash_ctx->blk_buf, SM3_BLK_BYTE_SIZE);
        hash_ctx->buf_len = 0;
        msg_len -= left_len;
        msg_tmp += left_len;
    }

    if (msg_len >= SM3_BLK_BYTE_SIZE) {
        calc_len = (msg_len / SM3_BLK_BYTE_SIZE) * SM3_BLK_BYTE_SIZE;
        sm3_data_blk_update(hash_ctx->iv, msg_tmp, calc_len);
        msg_len -= calc_len;
        msg_tmp += calc_len;
    }

    if (msg_len != 0) {
        if (hvb_check(hvb_memcpy_s(hash_ctx->blk_buf + hash_ctx->buf_len, sizeof(hash_ctx->blk_buf) - sizeof(hash_ctx->buf_len),
                                   msg_tmp, msg_len) != 0))
            return SM3_MEMORY_ERR;
        hash_ctx->buf_len += msg_len;
    }

    return SM3_OK;
}

#define SM3_PAD_BLK_WORD_SIZE     (SM3_BLK_WORD_SIZE * 2)
#define SM3_PAD_INFO_BYTE_LEN     8
static int sm3_pad_update(uint32_t *iv, const void *left_msg, uint32_t left_len, uint64_t total_bit_len)
{
    uint32_t pad_word_len;
    uint32_t sm3_pad[SM3_PAD_BLK_WORD_SIZE];
    uint8_t *pad_ptr = NULL;
    uint32_t fill_zero_len;
    int ret = -1;

    if (left_len != 0) {
        ret = hvb_memcpy_s(sm3_pad, sizeof(sm3_pad), left_msg, left_len);
        if (hvb_check(ret != 0)) {
            return SM3_MEMORY_ERR;
        }
    }

    pad_ptr = (uint8_t *)sm3_pad;
    pad_ptr[left_len] = 0x80;  // padding 0x80
    left_len++;

    if (left_len + SM3_PAD_INFO_BYTE_LEN <= SM3_BLK_BYTE_SIZE)
        pad_word_len = SM3_BLK_WORD_SIZE;
    else
        pad_word_len = SM3_PAD_BLK_WORD_SIZE;

    fill_zero_len = word2byte(pad_word_len) - (uint32_t)left_len - SM3_PAD_INFO_BYTE_LEN;
    ret = hvb_memset_s(pad_ptr + left_len, sizeof(sm3_pad) - left_len, 0, fill_zero_len);
    if (hvb_check(ret != 0))
        return SM3_MEMORY_ERR;

    sm3_pad[pad_word_len - 1] = htobe32((uint32_t)total_bit_len);
    total_bit_len = total_bit_len >> 32;
    sm3_pad[pad_word_len - 2] = htobe32((uint32_t)total_bit_len);

    sm3_data_blk_update(iv, pad_ptr, word2byte(pad_word_len));
    return SM3_OK;
}

static int sm3_output_iv(uint32_t *iv, uint8_t *out, uint32_t *out_len)
{
    if (hvb_check(out == NULL))
        return SM3_POINTER_NULL;

    if (hvb_check(out_len == NULL))
        return SM3_POINTER_NULL;

    if (hvb_check(*out_len < SM3_IV_BYTE_SIZE))
        return SM3_OUTBUF_NOT_ENOUGH;

    *out_len = SM3_IV_BYTE_SIZE;
    for (uint32_t i = 0; i < SM3_IV_WORD_SIZE; i++)
        iv[i] = htobe32(iv[i]);

    if (hvb_check(hvb_memcpy_s(out, *out_len, iv, SM3_IV_BYTE_SIZE) != 0))
        return SM3_MEMORY_ERR;

    return SM3_OK;
}

int hvb_sm3_final(struct sm3_ctx_t *hash_ctx, uint8_t *out, uint32_t *out_len)
{
    uint64_t total_bit_len;
    int ret = -1;

    if (hvb_check(hash_ctx == NULL))
        return SM3_POINTER_NULL;

    total_bit_len = hash_ctx->total_len * 8;
    if (hvb_check(total_bit_len <= hash_ctx->total_len))
        return SM3_OVER_MAX_LEN;

    ret = sm3_pad_update(hash_ctx->iv, hash_ctx->blk_buf, hash_ctx->buf_len, total_bit_len);
    if (hvb_check(ret != SM3_OK))
        return ret;

    return sm3_output_iv(hash_ctx->iv, out, out_len);
}

int hvb_sm3_single(const void *msg, uint32_t msg_len, uint8_t *out, uint32_t *out_len)
{
    uint32_t data_size;
    uint64_t total_bit_len;
    uint32_t iv[SM3_IV_WORD_SIZE];
    int ret = -1;

    /* 8bit per byte */
    total_bit_len = (uint64_t)msg_len * 8;

    if (hvb_check(msg == NULL))
        return SM3_POINTER_NULL;

    if (hvb_check(msg_len == 0))
        return SM3_MSG_LEN_ERR;

    if (hvb_check(hvb_memcpy_s(iv, sizeof(iv), sm3_iv_init, sizeof(sm3_iv_init)) != 0))
        return SM3_MEMORY_ERR;

    data_size = (msg_len / SM3_BLK_BYTE_SIZE) * SM3_BLK_BYTE_SIZE;

    if (data_size > 0)
        sm3_data_blk_update(iv, msg, data_size);

    ret = sm3_pad_update(iv, (uint8_t *)msg + data_size, msg_len - data_size, total_bit_len);
    if (hvb_check(ret != SM3_OK))
        return ret;

    return sm3_output_iv(iv, out, out_len);
}

#endif
