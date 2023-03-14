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
#include <stdlib.h>
#include "hvb_crypto.h"
#include "hvb_util.h"
#include "hvb_rsa.h"

enum {
    RESULT_OK = 0,
    ERROR_MEMORY_EMPTY,
    ERROR_MEMORY_NO_ENOUGH,
    ERROR_WORDLEN_ZERO,
};

#ifndef __WORDSIZE
#if defined(__LP64__)
#define __WORDSIZE 64
#elif defined(__LP32__)
#define __WORDSIZE 32
#else
#error "not support word size "
#endif
#endif

#define WORD_BYTE_SIZE sizeof(unsigned long)
#define WORD_BIT_SIZE (WORD_BYTE_SIZE * 8)
#define WORD_BIT_MASK (((1UL << WORD_BIT_SIZE) - 1))
#define byte2bit(byte) ((byte) << 3)
#define SWORD_BIT_SIZE (WORD_BIT_SIZE / 2)
#define SWORD_BIT_MASK ((1UL << SWORD_BIT_SIZE) - 1)

static void lin_clear(struct long_int_num *p_a)
{
    hvb_memset(p_a->data_mem, 0, p_a->mem_size);
}

static int lin_copy(struct long_int_num *p_src, struct long_int_num *p_dst)
{
    if (p_src->valid_word_len > p_dst->mem_size) {
        return ERROR_MEMORY_NO_ENOUGH;
    }

    hvb_memcpy(p_dst->p_uint, p_src->p_uint, p_src->valid_word_len * WORD_BYTE_SIZE);

    p_dst->valid_word_len = p_src->valid_word_len;

    return RESULT_OK;
}

static int lin_compare(struct long_int_num *p_a, struct long_int_num *p_b)
{
    int i;

    if (p_a->valid_word_len != p_b->valid_word_len) {
        return p_a->valid_word_len - p_b->valid_word_len;
    }

    for (i = p_a->valid_word_len - 1; i >= 0; --i) {
        if (p_a->p_uint[i] != p_b->p_uint[i]) {
            if (p_a->p_uint[i] > p_b->p_uint[i]) {
                return 1;
            }
            return -1;
        }
    }
    return 0;
}

static int lin_calloc(struct long_int_num *p_long_int, uint32_t word_len)
{
    unsigned long *p_data = NULL;

    if (word_len == 0) {
        return ERROR_WORDLEN_ZERO;
    }
    p_data = hvb_malloc(word_len * WORD_BYTE_SIZE);
    if (p_data == NULL) {
        return ERROR_MEMORY_EMPTY;
    }

    hvb_memset(p_data, 0, word_len * WORD_BYTE_SIZE);

    p_long_int->data_mem = p_data;
    p_long_int->mem_size = word_len * WORD_BYTE_SIZE;
    p_long_int->p_uint = p_data;
    p_long_int->valid_word_len = 0;

    return RESULT_OK;
}

struct long_int_num *lin_create(uint32_t word_len)
{
    struct long_int_num *p_res = NULL;

    p_res = hvb_malloc(sizeof(struct long_int_num));
    if (p_res == NULL) {
        return NULL;
    }

    if (lin_calloc(p_res, word_len) > 0) {
        hvb_free(p_res);
        return NULL;
    }
    p_res->valid_word_len = 0;
    return p_res;
}

void lin_free(struct long_int_num *p_long_int)
{
    if (!p_long_int) {
        return;
    }
    if (p_long_int->p_uint != NULL) {
        hvb_free(p_long_int->data_mem);
        p_long_int->p_uint = NULL;
    }
    hvb_free(p_long_int);

    return;
}

void lin_update_valid_len(struct long_int_num *p_a)
{
    unsigned long *p_data = NULL;
    uint32_t i;

    if (!p_a) {
        return;
    }

    p_data = p_a->p_uint + p_a->valid_word_len - 1;
    for (i = 0; i < p_a->valid_word_len; ++i) {
        if (*p_data != 0) {
            break;
        }
        --p_data;
    }
    p_a->valid_word_len -= i;
}

static void lin_mul_word(unsigned long a, unsigned long b, unsigned long *res_hi, unsigned long *res_low)
{
#if defined(__aarch64__)
    unsigned long hi;
    *res_low = a * b;
    __asm__ volatile ("umulh %0, %1, %2" : "+r"(hi) : "r"(a), "r"(b) :);
    *res_hi = hi;
#else

#if defined(__uint128_t)
    #if __WORDSIZE == 32
    unsigned long long aa;
#elif __WORDSIZE == 64
    __uint128_t aa, bb;
#else
    #error "not support word size "
#endif
    aa = a;
    bb = b;
    aa = aa * bb;
    *res_hi = aa >> WORD_BIT_SIZE;
    *res_low = aa & WORD_BIT_MASK;
#else
    unsigned long a_h, a_l;
    unsigned long b_h, b_l;
    unsigned long res_h, res_l;
    unsigned long c, t;
    a_h = a >> SWORD_BIT_SIZE;
    a_l = a & SWORD_BIT_MASK;
    b_h = b >> SWORD_BIT_SIZE;
    b_l = b & SWORD_BIT_MASK;

    res_h = a_h * b_h;
    res_l = a_l * b_l;

    c = a_h * b_l;
    res_h += c >> SWORD_BIT_SIZE;
    t = res_l;
    res_l += c << SWORD_BIT_SIZE;
    res_h += t > res_l;

    c = a_l * b_h;
    res_h += c >> SWORD_BIT_SIZE;
    t = res_l;
    res_l += c << SWORD_BIT_SIZE;
    res_h += t > res_l;
    *res_hi  = res_h;
    *res_low = res_l;
#endif
#endif
}

static void lin_sub(struct long_int_num *p_a, struct long_int_num *p_b)
{
    uint32_t i;
    unsigned long c;
    unsigned long t;

    c = 0;
    for (i = 0; i < p_b->valid_word_len; ++i) {
        t = p_a->p_uint[i] < c;
        p_a->p_uint[i] = p_a->p_uint[i] - c;

        c = (p_a->p_uint[i] < p_b->p_uint[i]) + t;
        p_a->p_uint[i] = p_a->p_uint[i] - p_b->p_uint[i];
    }
    for (; i < p_a->valid_word_len && c; ++i) {
        t = p_a->p_uint[i] < c;
        p_a->p_uint[i] = p_a->p_uint[i] - c;
        c = t;
    }
    lin_update_valid_len(p_a);
}

#define dword_add_word(a, b, r)		       \
    do {				       \
        r##_l = a##_l + (b);	       \
        r##_h = a##_h + (r##_l < (b)); \
    } while (0)

static void montgomery_mul_add(struct long_int_num *p_a, unsigned long b, struct long_int_num *p_n,
                               unsigned long n_n0_i, struct long_int_num *p_res)
{
    unsigned long x_h, x_l;
    unsigned long d0;
    unsigned long y_h, y_l;
    unsigned long t_h, t_l;
    unsigned long *p_ad = p_a->p_uint;
    unsigned long *p_nd = p_n->p_uint;
    unsigned long *p_rd = p_res->p_uint;
    uint32_t i;

    lin_mul_word(p_a->p_uint[0], b, &x_h, &x_l);

    dword_add_word(x, p_rd[0], x);

    d0 = x_l * n_n0_i;

    lin_mul_word(d0, p_nd[0], &y_h, &y_l);
    dword_add_word(y, x_l, y);

    for (i = 1; i < p_a->valid_word_len; ++i) {
        lin_mul_word(p_ad[i], b, &t_h, &t_l);
        dword_add_word(t, p_rd[i], t);
        dword_add_word(t, x_h, x);

        lin_mul_word(d0, p_nd[i], &t_h, &t_l);
        dword_add_word(t, x_l, t);
        dword_add_word(t, y_h, y);

        p_rd[i - 1] = y_l;
    }

    p_rd[i - 1] = x_h + y_h;

    p_res->valid_word_len = p_n->valid_word_len;
    if (p_rd[i - 1] < x_h) {
        lin_sub(p_res, p_n);
    }
}

static void montgomery_mod_mul(struct long_int_num *p_a, struct long_int_num *p_b, struct long_int_num *p_n,
                               unsigned long n_n0_i, struct long_int_num *p_res)
{
    uint32_t i;

    lin_clear(p_res);

    for (i = 0; i < p_b->valid_word_len; ++i) {
        montgomery_mul_add(p_a, p_b->p_uint[i], p_n, n_n0_i, p_res);
    }
}

struct long_int_num *montgomery_mod_exp(struct long_int_num *p_m, struct long_int_num *p_n, unsigned long n_n0_i,
                                        struct long_int_num *p_rr, uint32_t exp)
{
    struct long_int_num *p_res = NULL;
    struct long_int_num *p_mr = NULL;
    struct long_int_num *p_square = NULL;
    int i;
    if ((exp & 1UL) == 0) {
        goto fail_final;
    }

    p_mr = lin_create(p_n->valid_word_len);
    if (p_mr == NULL) {
        goto fail_final;
    }

    p_square = lin_create(p_n->valid_word_len);
    if (p_square == NULL) {
        goto fail_final;
    }

    p_res = lin_create(p_n->valid_word_len);
    if (p_res == NULL) {
        goto fail_final;
    }

    montgomery_mod_mul(p_m, p_rr, p_n, n_n0_i, p_mr);
    i = byte2bit(sizeof(exp)) - 1;
    for (; i >= 0; --i) {
        if (exp & (1UL << i)) {
            break;
        }
    }

    lin_copy(p_mr, p_res);

    for (--i; i > 0; --i) {
        montgomery_mod_mul(p_res, p_res, p_n, n_n0_i, p_square);
        if (exp & (1UL << i)) {
            montgomery_mod_mul(p_mr, p_square, p_n, n_n0_i, p_res);
        } else {
            lin_copy(p_square, p_res);
        }
    }
    montgomery_mod_mul(p_res, p_res, p_n, n_n0_i, p_square);
    montgomery_mod_mul(p_m, p_square, p_n, n_n0_i, p_res);

    if (lin_compare(p_res, p_n) >= 0) {
        lin_sub(p_res, p_n);
    }

fail_final:
    lin_free(p_mr);
    lin_free(p_square);

    return p_res;
}

int lin_get_bitlen(struct long_int_num *p_a)
{
    int i;
    int bit_len;
    unsigned long *p_data = NULL;
    unsigned long value;

    if (!p_a) {
        return 0;
    }
    p_data = p_a->p_uint;
    for (i = p_a->valid_word_len - 1; i >= 0; --i) {
        if (p_data[i] != 0) {
            break;
        }
    }

    bit_len = (i + 1) * WORD_BIT_SIZE;

    if (bit_len == 0) {
        return 0;
    }

    for (value = p_data[i]; ((signed long)value) > 0; value = value << 1) {
        --bit_len;
    }

    return bit_len;
}
