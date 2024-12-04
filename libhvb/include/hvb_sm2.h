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
#ifndef __HVB_SM2_H__
#define __HVB_SM2_H__

#include <stdint.h>

#define SM2_VERIFY_OK              0
#define SM2_POINTER_NULL           (-1)
#define SM2_PARAM_LEN_ERROR        (-2)
#define SM2_PARAM_ERROR            (-3)
#define SM2_COMPUTE_Z_ERROR        (-4)
#define SM2_COMPUTE_DIGEST_ERROR   (-5)
#define SM2_CHECK_RS_ERROR         (-6)
#define SM2_R_NOT_INDOMAIN         (-7)
#define SM2_S_NOT_INDOMAIN         (-8)
#define SM2_R_ADD_S_ERROR          (-9)
#define SM2_VERIFY_ERROR           (-10)
#define SM2_HASH_INIT_ERROR        (-11)
#define SM2_HASH_UPDATE_ERROR      (-12)
#define SM2_HASH_FINALE_ERROR      (-13)
#define SM2_MOD_ADD_ERROR          (-14)
#define SM2_POINT_MUL_ADD_ERROR    (-15)
#define SM2_KEY_LEN         32

struct sm2_pubkey {
    uint8_t x[SM2_KEY_LEN];
    uint8_t y[SM2_KEY_LEN];
};

int sm2_digest_verify(const struct sm2_pubkey *pkey, const uint8_t *pdigest, uint32_t digestlen,
    const uint8_t *psign, uint32_t signlen);

int hvb_sm2_verify(const struct sm2_pubkey *pkey, const uint8_t *pid, uint32_t idlen,
    const uint8_t *pmsg, uint32_t msglen, const uint8_t *psign, uint32_t signlen);
#endif
