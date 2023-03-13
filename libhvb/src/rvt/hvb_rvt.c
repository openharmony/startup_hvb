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

enum hvb_errno hvb_calculate_certs_digest(struct hvb_verified_data *vd, uint8_t *out_digest)
{
    uint64_t n;
    int ret = -1;
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

enum hvb_errno hvb_rvt_head_parser(const struct hvb_buf *rvt, struct rvt_image_header *header)
{
    uint64_t rvt_real_size;

    hvb_return_hvb_err_if_null(rvt);
    hvb_return_hvb_err_if_null(rvt->addr);
    hvb_return_hvb_err_if_null(header);

    if (rvt->size < sizeof(*header)) {
        hvb_print("error, rvt->size is too small.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    hvb_memcpy(header, rvt->addr, sizeof(*header));

    rvt_real_size = sizeof(*header) + header->verity_num * sizeof(struct rvt_pubk_desc);
    if (rvt_real_size > rvt->size || rvt_real_size < sizeof(*header)) {
        hvb_print("error, rvt_real_size is invalid.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    return HVB_OK;
}

enum hvb_errno hvb_rvt_get_pubk_desc(const struct hvb_buf *rvt, struct hvb_buf *pubk_desc)
{
    hvb_return_hvb_err_if_null(rvt);
    hvb_return_hvb_err_if_null(rvt->addr);
    hvb_return_hvb_err_if_null(pubk_desc);

    if (rvt->size < sizeof(*pubk_desc)) {
        hvb_print("error, rvt->size is too small.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    pubk_desc->addr = rvt->addr + sizeof(struct rvt_image_header);
    pubk_desc->size = rvt->size - sizeof(struct rvt_image_header);

    if (pubk_desc->size > rvt->size) {
        hvb_print("error, pubk_desc->size is invalid.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    return HVB_OK;
}

enum hvb_errno hvb_rvt_pubk_desc_parser(const struct hvb_buf *pubk, struct rvt_pubk_desc *desc)
{
    hvb_return_hvb_err_if_null(pubk);
    hvb_return_hvb_err_if_null(pubk->addr);
    hvb_return_hvb_err_if_null(desc);

    if (pubk->size < sizeof(*desc)) {
        hvb_print("error, pubk->size is too small.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    hvb_memcpy(desc, pubk->addr, sizeof(*desc));

    return HVB_OK;
}

enum hvb_errno hvb_rvt_get_pubk_buf(struct hvb_buf *key_buf, const struct hvb_buf *rvt, struct rvt_pubk_desc *desc)
{
    hvb_return_hvb_err_if_null(key_buf);
    hvb_return_hvb_err_if_null(rvt);
    hvb_return_hvb_err_if_null(rvt->addr);
    hvb_return_hvb_err_if_null(desc);

    key_buf->addr = rvt->addr + desc->pubkey_offset;
    key_buf->size = desc->pubkey_len;

    return HVB_OK;
}
