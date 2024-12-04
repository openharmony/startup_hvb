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
#ifndef __HVB_HASH_SM3_H__
#define __HVB_HASH_SM3_H__

#include <stdint.h>

#define SM3_BLK_WORD_SIZE 16
#define SM3_BLK_BYTE_SIZE (SM3_BLK_WORD_SIZE * sizeof(uint32_t))

#define SM3_IV_WORD_SIZE  8
#define SM3_IV_BYTE_SIZE  (SM3_IV_WORD_SIZE * sizeof(uint32_t))

#define SM3_OUT_BYTE_SIZE SM3_IV_BYTE_SIZE

#define SM3_OK                      0
#define SM3_POINTER_NULL            (-1)
#define SM3_BUF_LEN_ERR             (-2)
#define SM3_OVER_MAX_LEN            (-3)
#define SM3_OUTBUF_NOT_ENOUGH       (-4)
#define SM3_MSG_LEN_ERR             (-5)
#define SM3_MEMORY_ERR              (-6)
struct sm3_ctx_t {
    uint32_t buf_len;

    uint64_t total_len;

    uint32_t iv[SM3_IV_WORD_SIZE];

    uint8_t  blk_buf[SM3_BLK_BYTE_SIZE];
};

int hvb_sm3_init(struct sm3_ctx_t *hash_ctx);

int hvb_sm3_update(struct sm3_ctx_t *hash_ctx, const void *msg, uint32_t msg_len);

int hvb_sm3_final(struct sm3_ctx_t *hash_ctx, uint8_t *out, uint32_t *out_len);

int hvb_sm3_single(const void *msg, uint32_t msg_len, uint8_t *out, uint32_t *out_len);

#endif
