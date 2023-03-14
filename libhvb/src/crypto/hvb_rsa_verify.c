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
#include "hvb_hash_sha256.h"
#include "hvb_crypto.h"
#include "hvb_rsa.h"
#include "hvb_util.h"
#include "hvb_sysdeps.h"
#include "hvb_rsa_verify.h"


#define SHA256_DIGEST_LEN 32
#define PSS_EM_PADDING_LEN 2
#define PSS_MTMP_PADDING_LEN 8
#define PSS_DB_PADDING_LEN 1
#define PSS_END_PADDING_UNIT 0xBC
#define PSS_LEFTMOST_BIT_MASK 0xFFU

#define PADDING_UNIT_ZERO 0x00
#define PADDING_UNIT_ONE 0x01
#define RSA_WIDTH_MAX 8192

#define WORD_BYTE_SIZE sizeof(unsigned long)
#define WORD_BIT_SIZE (WORD_BYTE_SIZE * 8)
#define WORD_BIT_MASK (((1UL << WORD_BIT_SIZE) - 1))
#define bit2byte(bits) ((bits) >> 3)
#define byte2bit(byte) ((byte) << 3)
#define bit_val(x) (1U << (x))
#define bit_mask(x) (bit_val(x) - 1U)
#define bit_align(n, bit) (((n) + bit_mask(bit)) & (~(bit_mask(bit))))
#define bit2byte_align(bits) bit2byte(bit_align(bits, 3))
#define byte2dword(bytes) (((bytes) + (WORD_BYTE_SIZE) - 1) / WORD_BYTE_SIZE)
#define dword2byte(words) ((words) * WORD_BYTE_SIZE)

/* calc M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
static int emsa_pss_calc_m(const uint8_t *pdigest, uint32_t digestlen,
                           uint8_t *salt, uint32_t saltlen,
                           uint8_t **m)
{
    uint8_t *m_tmp = NULL;
    uint32_t m_tmp_len;

    m_tmp_len = digestlen + saltlen + PSS_MTMP_PADDING_LEN;
    m_tmp = (uint8_t *)hvb_malloc(m_tmp_len);
    if (!m_tmp) {
        return PARAM_EMPTY_ERROR;
    }

    hvb_memset(m_tmp, 0, PSS_MTMP_PADDING_LEN);
    hvb_memcpy(&m_tmp[PSS_MTMP_PADDING_LEN], pdigest, digestlen);

    if (saltlen != 0 && salt) {
        hvb_memcpy(&m_tmp[PSS_MTMP_PADDING_LEN + digestlen], salt, saltlen);
    }

    *m = m_tmp;
    return VERIFY_OK;
}

/* rsa verify last step compare hash value */
static int emsa_pss_hash_cmp(uint8_t *m_tmp, uint32_t m_tmp_len,
                             uint8_t *hash, uint32_t digestlen)
{
    int ret;
    uint8_t *hash_tmp = NULL;

    hash_tmp = (uint8_t *)hvb_malloc(digestlen);
    if (!hash_tmp) {
        return HASH_CMP_FAIL;
    }
    if (hash_sha256_single(m_tmp, m_tmp_len, hash_tmp, digestlen) != HASH_OK) {
        ret = HASH_CMP_FAIL;
        goto rsa_error;
    }
    /* compare twice */
    ret = VERIFY_OK;
    ret += hvb_memcmp(hash, hash_tmp, digestlen);
    ret += hvb_memcmp(hash, hash_tmp, digestlen);
    if (ret != VERIFY_OK)
        ret = HASH_CMP_FAIL;
rsa_error:
    hvb_free(hash_tmp);
    return ret;
}

static int rsa_pss_get_emlen(uint32_t klen, struct long_int_num *pn,
                             uint32_t *emlen, uint32_t *embits)
{
    *embits = lin_get_bitlen(pn);
    if (*embits == 0) {
        return CALC_EMLEN_ERROR;
    }
    (*embits)--;

    *emlen = bit2byte_align(*embits);
    if (*emlen == 0) {
        return CALC_EMLEN_ERROR;
    }

    if (*emlen > klen) {
        return CALC_EMLEN_ERROR;
    }

    return VERIFY_OK;
}

/* make generate function V1 */
static int rsa_gen_mask_mgf_v1(uint8_t *seed, uint32_t seed_len,
                               uint8_t *mask, uint32_t mask_len)
{
    int ret = VERIFY_OK;
    uint32_t cnt = 0;
    uint32_t cnt_maxsize = 0;
    uint8_t *p_tmp = NULL;
    uint8_t *pt = NULL;
    uint8_t *pc = NULL;
    const uint32_t hash_len = SHA256_DIGEST_LEN;

    /* Step 1: mask length is smaller than the maximum key length */
    if (mask_len > bit2byte(RSA_WIDTH_MAX)) {
        return CALC_MASK_ERROR;
    }

    /* Step 2:  Let pt and pt_tmp be the empty octet string. */
    pt = (uint8_t *)hvb_malloc(mask_len + hash_len);
    if (!pt) {
        return CALC_MASK_ERROR;
    }

    pc = (uint8_t *)hvb_malloc(seed_len + sizeof(uint32_t));
    if (!pc) {
        ret = CALC_MASK_ERROR;
        goto rsa_error;
    }

    /*
     * Step 3:  For counter from 0 to (mask_len + hash_len - 1) / hash_len ,
     * do the following:
     * string T:   T = T || Hash (pseed || counter)
     */
    p_tmp = pt;
    hvb_memcpy(pc, seed, seed_len);

    hvb_memset(pc + seed_len, 0, sizeof(uint32_t));
    /* step 3.1: count of Hash blocks needed for mask calculation */
    cnt_maxsize = (uint32_t)((mask_len + hash_len - 1) / hash_len);

    for (cnt = 0; cnt < cnt_maxsize; cnt++) {
        /* step 3.2: pt_tmp = pseed ||Counter */
        pc[seed_len + sizeof(uint32_t) - sizeof(uint8_t)] = cnt;

        /* step 3.3: calc T, T = T || Hash (pt_tmp) */
        if (hash_sha256_single(pc, seed_len + sizeof(uint32_t), p_tmp, hash_len) != HASH_OK) {
        ret = CALC_MASK_ERROR;
        goto rsa_error;
        }
        p_tmp += hash_len;
    }
    /* Step 4:  Output the leading L octets of T as the octet string mask. */
    hvb_memcpy(mask, pt, mask_len);

rsa_error:
    hvb_free(pt);
    hvb_free(pc);
    return ret;
}

static int emsa_pss_verify_check_db(uint8_t *db, uint32_t db_len,
                                    uint32_t emlen, uint32_t digestlen,
                                    uint32_t saltlen)
{
    int i;

    for (i = 0; i < emlen - digestlen - saltlen - PSS_EM_PADDING_LEN; i++) {
        if (db[i] != PADDING_UNIT_ZERO) {
            return CHECK_DB_ERROR;
        }
    }

    if (db[db_len - saltlen - PSS_DB_PADDING_LEN] != PADDING_UNIT_ONE) {
        return CMP_DB_FAIL;
    }

    return VERIFY_OK;
}

static int emsa_pss_verify(uint32_t saltlen, const uint8_t *pdigest,
                           uint32_t digestlen, uint32_t emlen,
                           uint32_t embits, uint8_t *pem)
{
    int ret;
    uint32_t i;
    uint32_t masklen;
    uint32_t m_tmp_len;
    uint32_t db_len = 0;
    uint8_t *hash = NULL;
    uint8_t *m_tmp = NULL;
    uint8_t *maskedb = NULL;
    uint8_t *salt = NULL;
    uint8_t *db = NULL;

    masklen = byte2bit(emlen) - embits;

    /*
     * Step 1: Skip digest calculate
     * Step 2: Check sizes, emLen < hLen + sLen + 2
     */
    if (emlen < digestlen + PSS_EM_PADDING_LEN || saltlen > (emlen - digestlen - PSS_EM_PADDING_LEN)) {
        return CALC_EMLEN_ERROR;
    }
    /* Step 3: if rightmost of EM is oxbc */
    if (pem[emlen - PSS_DB_PADDING_LEN] != PSS_END_PADDING_UNIT) {
        return CALC_0XBC_ERROR;
    }

    /* Step 4: set maskedDB and H */
    maskedb = pem;
    db_len = emlen - digestlen - PSS_DB_PADDING_LEN;
    hash = &pem[db_len];

    /* Step 5: Check that the leftmost bits in the leftmost octet of EM have the value 0 */
    if ((maskedb[0] & (~(PSS_LEFTMOST_BIT_MASK >> masklen))) != 0) {
        return CALC_EM_ERROR;
    }

    /* Step 6: calc dbMask, MGF(H) */
    db = (uint8_t *)hvb_malloc(db_len); /* db is dbmask */
    if (!db) {
        return CALC_DB_ERROR;
    }
    ret = rsa_gen_mask_mgf_v1(hash, digestlen, db, db_len);
    if (ret != VERIFY_OK) {
        goto rsa_error;
    }
    /* Step 7: calc db, maskedDB ^ db_mask */
    for (i = 0; i < db_len; i++) {
        db[i] = maskedb[i] ^ db[i];
    }

    /* Step 8: Set the leftmost 8*emLen-emBits bits in DB to zero */
    db[0] &= PSS_LEFTMOST_BIT_MASK >> masklen;

    /* Step 9: check db padding data */
    ret = emsa_pss_verify_check_db(db, db_len, emlen, digestlen, saltlen);
    if (ret != VERIFY_OK) {
        goto rsa_error;
    }
    /* Step 10: set salt be the last slen of DB */
    if (saltlen != 0) {
        salt = &db[db_len - saltlen];
    }

    /* Step 11: calc M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    ret = emsa_pss_calc_m(pdigest, digestlen, salt, saltlen, &m_tmp);
    if (ret != VERIFY_OK) {
        goto rsa_error;
    }
    /* Step 12: hash_tmp = H' = Hash(M') */
    m_tmp_len = PSS_MTMP_PADDING_LEN + digestlen + saltlen;
    ret = emsa_pss_hash_cmp(m_tmp, m_tmp_len, hash, digestlen);

rsa_error:
    hvb_free(db);
    hvb_free(m_tmp);
    return ret;
}

static inline void invert_copy(uint8_t *dst, uint8_t *src, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        dst[i] = src[len - i - 1];
    }
}

static int hvb_rsa_verify_pss_param_check(const struct hvb_rsa_pubkey *pkey, const uint8_t *pdigest,
                                          uint32_t digestlen, uint8_t *psign, uint32_t signlen)
{
    uint32_t klen;

    if (!pkey || !pdigest || !psign) {
        return PARAM_EMPTY_ERROR;
    }
    if (!pkey->pn || !pkey->p_rr || pkey->n_n0_i == 0) {
        return PUBKEY_EMPTY_ERROR;
    }
    klen = bit2byte(pkey->width);
    if (digestlen != SHA256_DIGEST_LEN) {
        return DIGEST_LEN_ERROR;
    }
    if (pkey->nlen != klen || pkey->rlen > pkey->nlen) {
        return PUBKEY_LEN_ERROR;
    }
    if (signlen > klen) {
        return SIGN_LEN_ERROR;
    }

    return VERIFY_OK;
}

static int hvb_rsa_verify_pss_param_convert(const struct hvb_rsa_pubkey *pkey, uint8_t *psign,
                                            uint32_t signlen, struct long_int_num *p_n,
                                            struct long_int_num *p_rr, struct long_int_num *p_m)
{
    invert_copy((uint8_t *)p_n->p_uint, pkey->pn, pkey->nlen);
    p_n->valid_word_len = byte2dword(pkey->nlen);
    lin_update_valid_len(p_n);
    if (!p_n) {
        return PUBKEY_EMPTY_ERROR;
    }

    invert_copy((uint8_t *)p_m->p_uint, psign, signlen);
    p_m->valid_word_len = byte2dword(pkey->nlen);
    lin_update_valid_len(p_m);
    if (!p_m) {
        return SIGN_EMPTY_ERROR;
    }

    invert_copy((uint8_t *)p_rr->p_uint, pkey->p_rr, pkey->rlen);
    p_rr->valid_word_len = byte2dword(pkey->nlen);
    lin_update_valid_len(p_rr);
    if (!p_rr) {
        return PUBKEY_EMPTY_ERROR;
    }

    return VERIFY_OK;
}

int hvb_rsa_verify_pss(const struct hvb_rsa_pubkey
                       *pkey, const uint8_t *pdigest,
                       uint32_t digestlen, uint8_t *psign,
                       uint32_t signlen, uint32_t saltlen)
{
    int ret;
    uint32_t klen;
    uint32_t emlen;
    uint32_t embits;
    unsigned long n_n0_i;
    struct long_int_num *p_n = NULL;
    struct long_int_num *p_m = NULL;
    struct long_int_num *p_rr = NULL;
    struct long_int_num *em = NULL;
    uint8_t *em_data = NULL;

    ret = hvb_rsa_verify_pss_param_check(pkey, pdigest, digestlen, psign, signlen);
    if (ret != VERIFY_OK) {
        return ret;
    }

    n_n0_i = (unsigned long)pkey->n_n0_i;
    klen = bit2byte(pkey->width);
    p_n = lin_create(byte2dword(pkey->nlen));
    if (!p_n) {
        return MEMORY_ERROR;
    }
    p_m = lin_create(byte2dword(pkey->nlen));
    if (!p_m) {
        ret = MEMORY_ERROR;
        goto rsa_error;
    }
    p_rr = lin_create(byte2dword(pkey->nlen));
    if (!p_rr) {
        ret = MEMORY_ERROR;
        goto rsa_error;
    }
    ret = hvb_rsa_verify_pss_param_convert(pkey, psign, signlen, p_n, p_rr, p_m);
    if (ret != VERIFY_OK) {
        goto rsa_error;
    }
    /* Step 1: RSA prim decrypt */
    em = montgomery_mod_exp(p_m, p_n, n_n0_i, p_rr, pkey->e);
    if (!em) {
        ret = MOD_EXP_CALC_FAIL;
        goto rsa_error;
    }
    em->valid_word_len = byte2dword(pkey->nlen);
    lin_update_valid_len(em);
    em_data = hvb_malloc(dword2byte(em->valid_word_len));
    if (!em_data) {
        ret = MOD_EXP_CALC_FAIL;
        goto rsa_error;
    }
    invert_copy(em_data, (uint8_t *)em->p_uint, dword2byte(em->valid_word_len));
    /* Step 2: emsa pss verify */
    ret = rsa_pss_get_emlen(klen, p_n, &emlen, &embits);
    if (ret != VERIFY_OK) {
        goto rsa_error;
    }
    if (klen - emlen == 1 && em_data[0] != 0) {
        ret = MOD_EXP_CALC_FAIL;
        goto rsa_error;
    }
    ret = emsa_pss_verify(saltlen, pdigest, digestlen, emlen, embits, em_data + klen - emlen);

rsa_error:
    lin_free(em);
    lin_free(p_n);
    lin_free(p_m);
    lin_free(p_rr);
    if (em_data) {
        hvb_free(em_data);
    }

    return ret;
}
