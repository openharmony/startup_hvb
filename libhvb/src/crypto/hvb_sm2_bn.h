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
#ifndef __HVB_SM2_BN_H__
#define __HVB_SM2_BN_H__

#include <stdint.h>
#include "hvb_gm_common.h"

#define SM2_SWORD_BIT_SIZE         32
#define SM2_KEY_LEN                32
#define SM2_DATA_DWORD_SIZE        4
#define SM2_BN_OK                  0
#define SM2_BN_INVALID             (-1)
#define SM2_BN_NOT_INDOMAIN        (-2)
#define SM2_BN_MEMORY_ERR          (-3)


struct sm2_point_jcb {
    uint64_t x[SM2_DATA_DWORD_SIZE];
    uint64_t y[SM2_DATA_DWORD_SIZE];
    uint64_t z[SM2_DATA_DWORD_SIZE];
};

struct sm2_point_aff {
    uint64_t x[SM2_DATA_DWORD_SIZE];
    uint64_t y[SM2_DATA_DWORD_SIZE];
};

void invert_copy_byte(uint8_t *dst, uint8_t *src, uint32_t len);

uint8_t *sm2_bn_get_param_a(void);

uint8_t *sm2_bn_get_param_b(void);

uint8_t *sm2_bn_get_param_gx(void);

uint8_t *sm2_bn_get_param_gy(void);

int sm2_bn_check_indomain_n(uint64_t a[]);

int sm2_bn_add_mod_n(uint64_t a[], uint64_t b[], uint64_t r[]);

int sm2_bn_is_valid(uint64_t a[]);

int sm2_bn_cmp(uint64_t a[], uint64_t b[]);

int sm2_point_mul_add(const uint64_t k1[], const uint64_t k2[], struct sm2_point_aff *p,
    struct sm2_point_aff *r);

#endif