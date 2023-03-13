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
#ifndef __HVB_RSA_H__
#define __HVB_RSA_H__

#include <stdint.h>

struct long_int_num {
    unsigned long *p_uint;
    unsigned long *data_mem;
    uint32_t mem_size;
    uint32_t valid_word_len;
};

struct long_int_num *lin_create(uint32_t word_len);
void lin_free(struct long_int_num *p_long_int);
void lin_update_valid_len(struct long_int_num *p_a);
int lin_get_bitlen(struct long_int_num *p_a);

/* The value of the |exp| power module |p_n| of |p_m| is calculated
* by using the algorithm of Montgomery module power.
*
* |n_n0_i| and |p_rr| are precomputed values stored in the public key.
*
* return the value of |p_m|^|exp| mod |p_m|
*/
struct long_int_num *montgomery_mod_exp(struct long_int_num *p_m, struct long_int_num *p_n,
                                        unsigned long n_n0_i, struct long_int_num *p_rr,
                                        uint32_t exp);

#endif
