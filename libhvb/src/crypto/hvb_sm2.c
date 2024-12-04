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
#include "hvb_sm2.h"
#include "hvb_sm3.h"
#include "hvb_sm2_bn.h"
#include "hvb_sysdeps.h"
#include "hvb_util.h"
#include <stdio.h>
#include <stdlib.h>

#define SM2_POINT_LEN   (SM2_KEY_LEN << 1)
/* user ID's max bits */
#define SM2_MAX_ID_BITS      65535
/* user ID's max len */
#define SM2_MAX_ID_LENGTH (SM2_MAX_ID_BITS / 8)

static int sm2_verify_check_param(const struct sm2_pubkey *pkey, const uint8_t *pid, uint32_t idlen,
                const uint8_t *pmsg, uint32_t msglen, const uint8_t *psign, uint32_t signlen)
{
    if (hvb_check(!pkey || !pid || !pmsg || !psign))
        return SM2_POINTER_NULL;

    if (hvb_check(signlen != SM2_POINT_LEN || idlen == 0 || msglen == 0 || idlen > SM2_MAX_ID_LENGTH))
        return SM2_PARAM_LEN_ERROR;

    return SM2_VERIFY_OK;
}

static int sm2_compute_z(const struct sm2_pubkey *pkey, const uint8_t *pid, uint32_t idlen,
                    uint8_t *pz, uint32_t *pzlen)
{
    int ret;
    uint16_t idx;
    struct sm3_ctx_t ctx = { 0 };

    ret = hvb_sm3_init(&ctx);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_INIT_ERROR;

    idx = (uint16_t)byte2bit(idlen);
    idx = u16_inv(idx);
    ret = hvb_sm3_update(&ctx, &idx, sizeof(idx));
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_UPDATE_ERROR;

    ret = hvb_sm3_update(&ctx, pid, idlen);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_UPDATE_ERROR;

    uint8_t *sm2_params[] = {
        sm2_bn_get_param_a(),
        sm2_bn_get_param_b(),
        sm2_bn_get_param_gx(),
        sm2_bn_get_param_gy(),
        (uint8_t *)pkey->x,
        (uint8_t *)pkey->y
    };

    for (idx = 0; idx < array_size(sm2_params); idx++) {
        ret = hvb_sm3_update(&ctx, sm2_params[idx], SM2_KEY_LEN);
        if (hvb_check(ret != SM3_OK))
            return SM2_HASH_UPDATE_ERROR;
    }

    ret = hvb_sm3_final(&ctx, pz, pzlen);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_FINALE_ERROR;

    return SM2_VERIFY_OK;
}

static int sm2_compute_digest(const uint8_t *pmsg, uint32_t msglen, const uint8_t *pz, uint32_t pzlen,
                    uint8_t *pdigest, uint32_t *pdigestlen)
{
    int ret;
    struct sm3_ctx_t ctx;

    ret = hvb_sm3_init(&ctx);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_INIT_ERROR;

    ret = hvb_sm3_update(&ctx, pz, pzlen);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_UPDATE_ERROR;

    ret = hvb_sm3_update(&ctx, pmsg, msglen);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_UPDATE_ERROR;

    ret = hvb_sm3_final(&ctx, pdigest, pdigestlen);
    if (hvb_check(ret != SM3_OK))
        return SM2_HASH_FINALE_ERROR;

    return SM2_VERIFY_OK;
}

static int sm2_check_rs(uint64_t r[], uint64_t s[], uint64_t t[])
{
    int ret;

    ret = sm2_bn_check_indomain_n(r);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_R_NOT_INDOMAIN;

    ret = sm2_bn_check_indomain_n(s);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_S_NOT_INDOMAIN;

    /* t = (r + s) mod n */
    ret = sm2_bn_add_mod_n(r, s, t);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_MOD_ADD_ERROR;

    ret = sm2_bn_is_valid(t);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_R_ADD_S_ERROR;

    return SM2_VERIFY_OK;
}

int sm2_digest_verify(const struct sm2_pubkey *pkey, const uint8_t *pdigest, uint32_t digestlen,
                    const uint8_t *psign, uint32_t signlen)
{
    int ret;
    uint64_t r[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t s[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t t[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t digest_tmp[SM2_DATA_DWORD_SIZE] = { 0 };
    struct sm2_point_aff tmp_point = { 0 };

    invert_copy_byte((uint8_t *)digest_tmp, (uint8_t *)pdigest, SM2_KEY_LEN);
    invert_copy_byte((uint8_t *)r, (uint8_t *)psign, SM2_KEY_LEN);
    invert_copy_byte((uint8_t *)s, (uint8_t *)psign + SM2_KEY_LEN, SM2_KEY_LEN);
    invert_copy_byte((uint8_t *)tmp_point.x, (uint8_t *)pkey->x, SM2_KEY_LEN);
    invert_copy_byte((uint8_t *)tmp_point.y, (uint8_t *)pkey->y, SM2_KEY_LEN);
    ret = sm2_check_rs(r, s, t);
    if (hvb_check(ret != SM2_VERIFY_OK))
        return ret;

    ret = sm2_point_mul_add(s, t, &tmp_point, &tmp_point);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_POINT_MUL_ADD_ERROR;

    ret = sm2_bn_add_mod_n(tmp_point.x, digest_tmp, t);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_MOD_ADD_ERROR;

    int ret_first = sm2_bn_cmp(r, t);
    int ret_second = sm2_bn_cmp(r, t);
    if (hvb_check(ret_first != 0 || ret_second != 0))
        return SM2_VERIFY_ERROR;

    return SM2_VERIFY_OK + ret_first + ret_second;
}

int hvb_sm2_verify(const struct sm2_pubkey *pkey, const uint8_t *pid, uint32_t idlen,
                const uint8_t *pmsg, uint32_t msglen, const uint8_t *psign, uint32_t signlen)
{
    uint8_t pz[SM3_OUT_BYTE_SIZE] = { 0 };
    uint8_t pdigest[SM3_OUT_BYTE_SIZE] = { 0 };
    uint32_t zlen = SM3_OUT_BYTE_SIZE;
    uint32_t digestlen = SM3_OUT_BYTE_SIZE;
    int ret;

    ret = sm2_verify_check_param(pkey, pid, idlen, pmsg, msglen, psign, signlen);
    if (hvb_check(ret != SM2_VERIFY_OK))
        return SM2_PARAM_ERROR;

    ret = sm2_compute_z(pkey, pid, idlen, pz, &zlen);
    if (hvb_check(ret != SM2_VERIFY_OK))
        return SM2_COMPUTE_Z_ERROR;

    ret = sm2_compute_digest(pmsg, msglen, pz, zlen, pdigest, &digestlen);
    if (hvb_check(ret != SM2_VERIFY_OK))
        return SM2_COMPUTE_DIGEST_ERROR;

    return sm2_digest_verify(pkey, pdigest, digestlen, psign, signlen);
}
