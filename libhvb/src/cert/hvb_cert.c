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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hvb.h"
#include "hvb_util.h"
#include "hvb_crypto.h"
#include "hvb_sysdeps.h"
#include "hvb_cert.h"


static bool hvb_need_verify_hash(const char *const *hash_ptn_list, const char *ptn)
{
    size_t n;
    size_t ptn_len = hvb_strlen(ptn);

    if (hash_ptn_list == NULL)
        return false;

    for (n = 0; hash_ptn_list[n] != NULL; n++) {
        if (hvb_strlen(hash_ptn_list[n]) == ptn_len &&
            hvb_memcmp(hash_ptn_list[n], ptn, ptn_len) == 0)
            return true;
    }

    return false;
}

static uint64_t get_hash_size(uint32_t algo)
{
    switch (algo) {
        case 0: // SHA256_RSA3072
        case 1: // SHA256_RSA4096
        case 2: // SHA256_RSA2048
            return 32;
        default:
            return 0;
    }

    return 0;
}

static enum hvb_errno hvb_compare_hash(struct hvb_buf *digest_buf, struct hvb_buf *msg_buf,
                                       struct hvb_buf *salt_buf, uint32_t hash_algo)
{
    int hash_err;
    struct hash_ctx_t ctx = {0};
    uint8_t computed_hash[HVB_HASH_MAX_BYTES] = {0};

    uint32_t computed_hash_size = get_hash_size(hash_algo);
    if (computed_hash_size != digest_buf->size) {
        hvb_print("computed_hash_size error\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    hash_err = hash_ctx_init(&ctx, hash_algo);
    if (hash_err != HASH_OK) {
        hvb_print("hash init error\n");
        return HVB_ERROR_VERIFY_HASH;
    }

    hash_err = hash_calc_update(&ctx, salt_buf->addr, salt_buf->size);
    if (hash_err != HASH_OK) {
        hvb_print("hash updata salt error\n");
        return HVB_ERROR_VERIFY_HASH;
    }

    hash_err = hash_calc_do_final(&ctx, msg_buf->addr, msg_buf->size, &computed_hash[0], digest_buf->size);
    if (hash_err != HASH_OK) {
        hvb_print("hash updata msg error\n");
        return HVB_ERROR_VERIFY_HASH;
    }

    if (hvb_memcmp(&computed_hash[0], digest_buf->addr, computed_hash_size) != 0) {
        hvb_print("compare fail\n");
        return HVB_ERROR_VERIFY_HASH;
    }

    return HVB_OK;
}

static enum hvb_errno hash_image_init_desc(struct hvb_ops *ops, const char *ptn,
                                           struct hvb_cert *cert, const char *const *hash_ptn_list,
                                           struct hvb_verified_data *vd)
{
    enum hvb_io_errno io_ret = HVB_IO_OK;
    enum hvb_errno ret = HVB_OK;
    struct hvb_buf image_buf = {NULL, 0};
    struct hvb_buf salt_buf = {cert->hash_payload.salt, cert->salt_size};
    struct hvb_buf digest_buf = {cert->hash_payload.digest, cert->digest_size};
    uint64_t read_bytes = 0;
    struct hvb_image_data *image = NULL;
    enum hvb_image_type image_type = (enum hvb_image_type)cert->verity_type;

    if (image_type != HVB_IMAGE_TYPE_HASH || !hvb_need_verify_hash(hash_ptn_list, ptn)) {
        hvb_printv(ptn, ": no need verify hash image.\n", NULL);
        return HVB_OK;
    }

    image_buf.size = cert->image_original_len;
    image_buf.addr = hvb_malloc(image_buf.size);
    if (image_buf.addr == NULL) {
        hvb_print("malloc image_buf fail\n");
        return HVB_ERROR_OOM;
    }

    io_ret = ops->read_partition(ops, ptn, 0, image_buf.size, image_buf.addr, &read_bytes);
    if (io_ret != HVB_IO_OK) {
        hvb_printv(ptn, ": Error loading data.\n", NULL);
        ret = HVB_ERROR_IO;
        goto out;
    }
    if (read_bytes != image_buf.size) {
        hvb_printv(ptn, ": Read incorrect number of bytes from.\n", NULL);
        ret = HVB_ERROR_IO;
        goto out;
    }

    ret = hvb_compare_hash(&digest_buf, &image_buf, &salt_buf, cert->hash_algo);
    if (ret != HVB_OK) {
        hvb_printv(ptn, ": compare hash error.\n", NULL);
        goto out;
    }

    if (vd->num_loaded_images >= HVB_MAX_NUMBER_OF_LOADED_IMAGES) {
        hvb_print("error, too many images\n");
        ret = HVB_ERROR_OOM;
        goto out;
    }

    image = &vd->images[vd->num_loaded_images++];
    image->partition_name = hvb_strdup(ptn);
    image->data = image_buf;
    image->preloaded = true;

    return HVB_OK;

out:
    if (image_buf.addr != NULL)
        hvb_free(image_buf.addr);

    return ret;
}

static bool _decode_octets(struct hvb_buf *buf, size_t size, uint8_t **p, uint8_t *end)
{
    /* check range */
    if (*p + size > end || *p + size < *p)
        return false;

    buf->addr = *p;
    buf->size = size;

    /* forward move */
    *p += size;

    return true;
}

static enum hvb_errno _hvb_cert_payload_parser(struct hvb_cert *cert, uint8_t **p, uint8_t *end)
{
    struct hvb_buf buf;
    struct hash_payload *payload = &cert->hash_payload;

    if (!_decode_octets(&buf, cert->salt_size, p, end)) {
        hvb_print("error, dc salt.\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }
    payload->salt = buf.addr;

    if (!_decode_octets(&buf, cert->digest_size, p, end)) {
        hvb_print("error, dc digest.\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }
    payload->digest = buf.addr;

    return HVB_OK;
}

static enum hvb_errno _hvb_cert_signature_parser(struct hvb_cert *cert, uint8_t **p, uint8_t *end)
{
    struct hvb_buf buf;
    struct hvb_sign_info *sign_info = &cert->signature_info;
    size_t cp_size = hvb_offsetof(struct hvb_sign_info, pubk);

    if (!_decode_octets(&buf, cp_size, p, end)) {
        hvb_print("error, dc sign info const.\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }
    hvb_memcpy(&cert->signature_info, buf.addr, cp_size);

    if (!_decode_octets(&buf, sign_info->pubkey_len, p, end)) {
        hvb_print("error, dc pubk.\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }

    hvb_memcpy(&sign_info->pubk, &buf, sizeof(buf));

    if (!_decode_octets(&buf, sign_info->signature_len, p, end)) {
        hvb_print("error, dc sign.\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }

    hvb_memcpy(&sign_info->sign, &buf, sizeof(buf));

    return HVB_OK;
}

enum hvb_errno hvb_cert_parser(struct hvb_cert *cert, struct hvb_buf *cert_buf)
{
    enum hvb_errno ret = HVB_OK;
    struct hvb_buf buf;
    uint8_t *p = cert_buf->addr;
    uint8_t *end = p + cert_buf->size;
    size_t header_size = hvb_offsetof(struct hvb_cert, hash_payload);

    /* parse header */
    if (!_decode_octets(&buf, header_size, &p, end)) {
        hvb_print("error, dc cert const.\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }

    hvb_memcpy(cert, buf.addr, buf.size);

    /* parse hash payload */
    ret = _hvb_cert_payload_parser(cert, &p, end);
    if (ret != HVB_OK) {
        hvb_print("error, pr hash payload.\n");
        return ret;
    }

    /* parse signature info */
    ret = _hvb_cert_signature_parser(cert, &p, end);
    if (ret != HVB_OK) {
        hvb_print("error, pr sign.\n");
        return ret;
    }

    return HVB_OK;
}

static uint64_t hvb_buftouint64(uint8_t *p)
{
    uint32_t i;
    uint64_t val = 0;

    for (i = 0; i < 8; i++, p++) {
        val |= (((uint64_t)(*p)) << (i * 8));
    }

    return val;
}

/*
 * raw_pubk: |bit_length|n0|mod|p_rr|
 */
static enum hvb_errno hvb_cert_pubk_parser(struct hvb_rsa_pubkey *pubk, struct hvb_buf *raw_pubk)
{
    uint64_t bit_length = 0;
    uint64_t n0 = 0;
    struct hvb_buf mod;
    struct hvb_buf p_rr;
    struct hvb_buf buf;

    uint8_t *p = raw_pubk->addr;
    uint8_t *end = p + raw_pubk->size;

    if (!_decode_octets(&buf, sizeof(uint64_t), &p, end)) {
        hvb_print("error, dc bit_length.\n");
        return 1;
    }
    bit_length = hvb_buftouint64(buf.addr);
    bit_length = hvb_be64toh(bit_length);

    if (!_decode_octets(&buf, sizeof(uint64_t), &p, end)) {
        hvb_print("error, dc n0.\n");
        return 1;
    }
    n0 = hvb_buftouint64(buf.addr);
    n0 = hvb_be64toh(n0);

    if (!_decode_octets(&mod, bit_length / 8, &p, end)) {
        hvb_print("error, dc mod.\n");
        return 1;
    }

    if (!_decode_octets(&p_rr, bit_length / 8, &p, end)) {
        hvb_print("error, dc p_rr\n");
        return 1;
    }

    pubk->width = bit_length;
    pubk->e = 65537;
    pubk->pn = mod.addr;
    pubk->nlen = mod.size;
    pubk->p_rr = p_rr.addr;
    pubk->rlen = p_rr.size;
    pubk->n_n0_i = n0;

    return 0;
}

static enum hvb_errno hvb_verify_cert(struct hvb_buf *tbs, struct hvb_sign_info *sign_info, uint32_t salt_size)
{
    int cry_err;
    enum hvb_errno ret = HVB_OK;
    uint32_t hash_len;
    struct hvb_buf temp_buf;
    uint8_t *hash = NULL;
    struct hvb_rsa_pubkey pubk;

    temp_buf = sign_info->pubk;
    ret = hvb_cert_pubk_parser(&pubk, &temp_buf);
    if (ret != HVB_OK) {
        hvb_print("error, hvb cert pubk parser.\n");
        return ret;
    }

    hash_len = get_hash_size(sign_info->algorithm);
    hash = hvb_malloc(hash_len);
    if (!hash) {
        hvb_print("hash malloc error:");
        return HVB_ERROR_OOM;
    }

    cry_err = hash_sha256_single(tbs->addr, tbs->size, hash, hash_len);
    if (cry_err != 0) {
        hvb_print("Error computed hash.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    cry_err = hvb_rsa_verify_pss(&pubk, hash, hash_len, sign_info->sign.addr, sign_info->sign.size, salt_size);
    if (cry_err != VERIFY_OK) {
        hvb_print("hvb_rsa_verify_pss result error, signature mismatch\n");
        return HVB_ERROR_VERIFY_SIGN;
    }

    return HVB_OK;
}

static enum hvb_errno _check_rollback_index(struct hvb_ops *ops, struct hvb_cert *cert, struct hvb_verified_data *vd)
{
    enum hvb_io_errno io_ret = HVB_IO_OK;
    uint64_t stored_rollback_index = 0;
    uint64_t cert_rollback_index = cert->rollback_index;
    uint64_t rollback_location = cert->rollback_location;

    if (rollback_location >= HVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS) {
        hvb_print("error, rollback_location too big\n");
        return HVB_ERROR_INVALID_CERT_FORMAT;
    }

    io_ret = ops->read_rollback(ops, rollback_location, &stored_rollback_index);
    if (io_ret != HVB_IO_OK) {
        hvb_print("error, read rollback idnex\n");
        return HVB_ERROR_IO;
    }

    if (cert_rollback_index < stored_rollback_index) {
        hvb_print("error, cert rollback index is less than the stored\n");
        return HVB_ERROR_ROLLBACK_INDEX;
    }

    vd->rollback_indexes[rollback_location] = cert_rollback_index;

    return HVB_OK;
}

enum hvb_errno cert_init_desc(struct hvb_ops *ops, const char *ptn, struct hvb_buf *cert_buf,
                              const char *const *hash_ptn_list, struct hvb_buf *out_pubk,
                              struct hvb_verified_data *vd)
{
    enum hvb_errno ret = HVB_OK;
    struct hvb_cert cert = {0};
    struct hvb_buf tbs = {0};
    struct hvb_sign_info *sign_info = &cert.signature_info;

    ret = hvb_cert_parser(&cert, cert_buf);
    if (ret != HVB_OK) {
        hvb_print("error, hvb cert parser.\n");
        return ret;
    }

    tbs.addr = cert_buf->addr;
    tbs.size = sign_info->sign.addr - cert_buf->addr;
    ret = hvb_verify_cert(&tbs, sign_info, cert.salt_size);
    if (ret != HVB_OK) {
        hvb_print("error, verify cert.\n");
        return ret;
    }

    ret = _check_rollback_index(ops, &cert, vd);
    if (ret != HVB_OK) {
        hvb_print("error, checkout index.\n");
        return ret;
    }

    ret = hash_image_init_desc(ops, ptn, &cert, hash_ptn_list, vd);
    if (ret != HVB_OK) {
        hvb_print("hash_image_init_desc result error\n");
        return ret;
    }

    *out_pubk = sign_info->pubk;

    return ret;
}
