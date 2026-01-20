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
#include "hvb_rvt.h"
#include "hvb_ops.h"
#include "hvb_cert.h"
#include "hvb_util.h"
#include "hvb_sm3.h"

static enum hvb_errno hvb_calculate_certs_digest_rsa(struct hvb_verified_data *vd, uint8_t *out_digest)
{
    uint64_t n;
    int ret;
    struct hash_ctx_t ctx;

    ret = hash_ctx_init(&ctx, HASH_ALG_SHA256);
    if (ret != HASH_OK) {
        hvb_print("error, hash_ctx_init.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    for (n = 0; n < vd->num_loaded_certs; n++) {
        ret = hash_calc_update(&ctx, vd->certs[n].data.addr, vd->certs[n].data.size);
        if (ret != HASH_OK) {
            hvb_print("error, hash_calc_update.\n");
            return HVB_ERROR_INVALID_ARGUMENT;
        }
    }

    ret = hash_calc_do_final(&ctx, NULL, 0, out_digest, HVB_SHA256_DIGEST_BYTES);
    if (ret != HASH_OK) {
        hvb_print("error, hash_calc_do_final.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    return HVB_OK;
}

static enum hvb_errno hvb_calculate_certs_digest_sm(struct hvb_verified_data *vd, uint8_t *out_digest)
{
    uint64_t n;
    uint32_t out_len = HVB_SM3_DIGEST_BYTES;
    int ret;
    struct sm3_ctx_t ctx;

    if (vd == NULL || out_digest == NULL) {
        hvb_print("arguments are invalid in hvb_calculate_certs_digest_sm\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    ret = hvb_sm3_init(&ctx);
    if (ret != SM3_OK) {
        hvb_print("error, hash_ctx_init.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    for (n = 0; n < vd->num_loaded_certs; n++) {
        ret = hvb_sm3_update(&ctx, vd->certs[n].data.addr, vd->certs[n].data.size);
        if (ret != SM3_OK) {
            hvb_print("error, hash_calc_update.\n");
            return HVB_ERROR_INVALID_ARGUMENT;
        }
    }

    ret = hvb_sm3_final(&ctx, out_digest, &out_len);
    if (ret != SM3_OK) {
        hvb_print("error, hash_calc_do_final.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    return HVB_OK;
}

enum hvb_errno hvb_calculate_certs_digest(struct hvb_verified_data *vd, uint8_t *out_digest)
{
    hvb_return_hvb_err_if_null(vd);

    switch (vd->algorithm) {
        case 0: // SHA256_RSA3072
        case 1: // SHA256_RSA4096
        case 2: // SHA256_RSA2048
            return hvb_calculate_certs_digest_rsa(vd, out_digest);
        case 3: // sm2_sm3
            return hvb_calculate_certs_digest_sm(vd, out_digest);
        default: {
            hvb_print("hvb_calculate_certs_digest error: invalid algorithm\n");
            return HVB_ERROR_INVALID_ARGUMENT;
        }
    }
}

enum hvb_errno hvb_rvt_head_parser(const struct hvb_buf *rvt, struct rvt_image_header *header)
{
    hvb_return_hvb_err_if_null(rvt);
    hvb_return_hvb_err_if_null(rvt->addr);
    hvb_return_hvb_err_if_null(header);

    if (rvt->size < sizeof(*header)) {
        hvb_print("error, rvt->size is too small.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    if (rvt->size > RVT_MAX_SIZE) {
        hvb_print("error, rvt->size is too large.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    /* copy desc const part */
    if (hvb_memcpy_s(header, sizeof(*header), rvt->addr, sizeof(*header)) != 0) {
        hvb_print("error, copy rvt header.\n");
        return HVB_ERROR_OOM;
    }

    if (header->pubkey_num_per_ptn > RVT_MAX_VALID_KEY_NUM) {
        hvb_print("error, invalid pubkey_num_per_ptn.\n");
        return HVB_ERROR_OOM;
    }

    if (header->verity_num >= MAX_NUMBER_OF_RVT_IMAGES) {
        hvb_print("error, verity_num.\n");
        return HVB_ERROR_OOM;
    }

    return HVB_OK;
}

enum hvb_errno hvb_rvt_get_pubk_desc(const struct hvb_buf *rvt, struct hvb_buf *pubk_desc)
{
    hvb_return_hvb_err_if_null(rvt);
    hvb_return_hvb_err_if_null(rvt->addr);
    hvb_return_hvb_err_if_null(pubk_desc);

    if (rvt->size < sizeof(struct rvt_image_header)) {
        hvb_print("error, rvt->size is too small.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    if (rvt->size > RVT_MAX_SIZE) {
        hvb_print("error, rvt->size is too large.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    pubk_desc->addr = rvt->addr + sizeof(struct rvt_image_header);
    pubk_desc->size = rvt->size - sizeof(struct rvt_image_header);

    return HVB_OK;
}

enum hvb_errno hvb_rvt_pubk_desc_parser(const struct hvb_buf *pubk, struct rvt_pubk_desc *desc)
{
    size_t pubk_desc_const_size = hvb_offsetof(struct rvt_pubk_desc, pubkey_payload);
    hvb_return_hvb_err_if_null(pubk);
    hvb_return_hvb_err_if_null(pubk->addr);
    hvb_return_hvb_err_if_null(desc);

    if (pubk->size < pubk_desc_const_size) {
        hvb_print("error, pubk->size is too small.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }
    if (hvb_memcpy_s(desc, sizeof(*desc), pubk->addr, pubk_desc_const_size) != 0) {
        hvb_print("error, copy desc.\n");
        return HVB_ERROR_OOM;
    }

    return HVB_OK;
}

enum hvb_errno hvb_rvt_get_pubk_buf(struct hvb_buf *key_buf, const struct hvb_buf *rvt,
                                    uint32_t pubkey_offset, uint32_t pubkey_len)
{
    hvb_return_hvb_err_if_null(key_buf);
    hvb_return_hvb_err_if_null(rvt);
    hvb_return_hvb_err_if_null(rvt->addr);

    key_buf->addr = rvt->addr + pubkey_offset;
    key_buf->size = pubkey_len;

    return HVB_OK;
}
