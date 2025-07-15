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
#include "hvb_sm2_bn.h"
#include <hvb_sysdeps.h>
#include <stdio.h>
#include <stdlib.h>

#define SM2_DATA_MUL_DWORD_SIZE         (SM2_DATA_DWORD_SIZE * 2)
#define SM2_DATA_BIT_SIZE               256
#define SM2_BIT_PER_BYTE                8
#define SM2_SWORD_BIT_MASK              ((1UL << SM2_SWORD_BIT_SIZE) - 1)
#define SM2_BIT_PER_LONG                64
#define SLIDING_WINDOW_SIZE             5
#define SLIDING_WINDOW_PRE_TABLE_SIZE   (1 << (SLIDING_WINDOW_SIZE - 1))
#define get_low_64bits(a)               ((a) & 0xFFFFFFFFFFFFFFFF)
#define get_high_64bits(a)              ((__uint128_t)(a) >> 64)
#define get_low_32bits(a)               ((a) & 0xFFFFFFFF)
#define get_high_32bits(a)              ((uint64_t)(a) >> 32)

struct sm2_point_scalar_encode_info {
    /* encode res per window */
    int8_t code_num[SM2_DATA_BIT_SIZE / SLIDING_WINDOW_SIZE + 1];
    /* bit num that cur window distance from last window */
    uint16_t shift_bit[SM2_DATA_BIT_SIZE / SLIDING_WINDOW_SIZE + 1];
    /* window num */
    uint32_t window_num;
    /* the first bit exclued the first code_num */
    uint32_t start_bit;
};


/* 2 ^ 256 - p */
const uint64_t g_negative_p[] = {0x1, 0xffffffff, 0x0, 0x100000000};
/* 2 ^ 256 - n */
const uint64_t g_negative_n[] = {0xAC440BF6C62ABEDD, 0x8DFC2094DE39FAD4, 0x0, 0x100000000};
const uint64_t g_p[] = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF };
const uint64_t g_n[] = { 0x53BBF40939D54123, 0x7203DF6B21C6052B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF };
const uint64_t g_a_bigendian[] = { 0xFFFFFFFFFEFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0xFCFFFFFFFFFFFFFF };
const uint64_t g_b_bigendian[] = { 0x345E9F9D9EFAE928, 0xA70965CF4B9E5A4D, 0x928FAB15F58997F3, 0x930E944D41BDBCDD };
const uint64_t g_gx_bigendian[] = { 0x1981191F2CAEC432, 0x94C9396A4604995F, 0xE10B66F2BF0BE38F, 0xC7744C3389455A71 };
const uint64_t g_gy_bigendian[] = { 0x9C77F6F4A23637BC, 0x5321696BE3CEBD59, 0x40472AC67C87A9D0, 0xA0F03921E532DF02 };
const struct sm2_point_jcb g_pointg = {
    .x = { 0x715A4589334C74C7, 0x8FE30BBFF2660BE1, 0x5F9904466A39C994, 0x32C4AE2C1F198119 },
    .y = { 0x02DF32E52139F0A0, 0xD0A9877CC62A4740, 0x59BDCEE36B692153, 0xBC3736A2F4F6779C },
    .z = { 1, 0, 0, 0 }
};

/*
 * r = a + b + c, the param 'carry' means carry of sum
 * note that c and r can't be the same
 */
static void add_with_carry(uint64_t a, uint64_t b, uint64_t c, uint64_t *r, uint64_t *carry)
{
    uint64_t tmp_res = a + c;
    *carry = tmp_res >= a ? 0 : 1;
    tmp_res += b;
    *carry += tmp_res >= b ? 0 : 1;
    *r = tmp_res;
}

/*
 * r = a - b - c, the param 'borrow' means borrow of sub
 * note that c and r can't be the same
 */
static void sub_with_borrow(uint64_t a, uint64_t b, uint64_t c, uint64_t *r, uint64_t *borrow)
{
    uint64_t tmp_borrow = a >= b ? 0 : 1;
    *r = a - b;
    tmp_borrow += *r >= c ? 0 : 1;
    *r -= c;
    *borrow = tmp_borrow;
}

/* a = a >> 1 */
#define shift_right_one_bit(a)                \
    do {                                      \
        (a[0] = (a[0] >> 1) + (a[1] << 63));    \
        (a[1] = (a[1] >> 1) + (a[2] << 63));    \
        (a[2] = (a[2] >> 1) + (a[3] << 63));    \
        (a[3] = a[3] >> 1);                     \
    } while (0)

/* a = (a + p) >> 1 */
#define add_p_shift_right_one_bit(a)                           \
    do {                                                       \
        uint64_t carry = 0;                                    \
        for (uint32_t i = 0; i < SM2_DATA_DWORD_SIZE; i++) {   \
            add_with_carry((a[i]), (g_p[i]), (carry), &(a[i]), &(carry));  \
        }                                                      \
        (a[0] = (a[0] >> 1) + (a[1] << 63));                     \
        (a[1] = (a[1] >> 1) + (a[2] << 63));                     \
        (a[2] = (a[2] >> 1) + (a[3] << 63));                     \
        (a[3] = (a[3] >> 1) + (carry << 63));                    \
    } while (0)

void invert_copy_byte(uint8_t *dst, uint8_t *src, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        dst[i] = src[len - i - 1];
}

/* get sm2 curve param a */
uint8_t *sm2_bn_get_param_a(void)
{
    return (uint8_t *)g_a_bigendian;
}

/* get sm2 curve param b */
uint8_t *sm2_bn_get_param_b(void)
{
    return (uint8_t *)g_b_bigendian;
}

/* get sm2 curve param Gx */
uint8_t *sm2_bn_get_param_gx(void)
{
    return (uint8_t *)g_gx_bigendian;
}

/* get sm2 curve param Gy */
uint8_t *sm2_bn_get_param_gy(void)
{
    return (uint8_t *)g_gy_bigendian;
}

/*
 * r = (a + b) mod p, p is SM2 elliptic curve param
 * note that this function only ensure r is 256bits, can't ensure r < p
 */
static void sm2_bn_add_mod_p(uint64_t a[], uint64_t b[], uint64_t r[])
{
    uint64_t carry = 0;
    uint32_t i = 0;

    for (i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
        add_with_carry(a[i], b[i], carry, &r[i], &carry);
    }

    while (carry == 1) {
        carry = 0;
        for (i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
            add_with_carry(r[i], g_negative_p[i], carry, &r[i], &carry);
        }
    }
}

/*
 * r = (a + b) mod n, n is SM2 elliptic curve param
 */
int sm2_bn_add_mod_n(uint64_t a[], uint64_t b[], uint64_t r[])
{
    uint64_t carry = 0;
    uint32_t i = 0;
    uint64_t r_tmp[SM2_DATA_DWORD_SIZE] = { 0 };
    int ret = -1;

    for (i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
        add_with_carry(a[i], b[i], carry, &r[i], &carry);
    }

    while (carry == 1) {
        carry = 0;
        for (i = 0; i < SM2_DATA_DWORD_SIZE; i++)
            add_with_carry(r[i], g_negative_n[i], carry, &r[i], &carry);
    }

    for (i = 0; i < SM2_DATA_DWORD_SIZE; i++)
        sub_with_borrow(r[i], g_n[i], carry, &r_tmp[i], &carry);

    if (carry == 0) {
        ret = hvb_memcpy_s(r, SM2_KEY_LEN, r_tmp, sizeof(r_tmp));
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;
    }

    return SM2_BN_OK;
}

/*
 * r = (a - b) mod p, p is SM2 elliptic curve param
 * note that this function only ensure r is 256bits, can't ensure r < p
 */
static void sm2_bn_sub_mod_p(uint64_t a[], uint64_t b[], uint64_t r[])
{
    uint64_t borrow = 0;
    uint32_t i = 0;

    for (i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
        sub_with_borrow(a[i], b[i], borrow, &r[i], &borrow);
    }

    while (borrow == 1) {
        borrow = 0;
        for (i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
            sub_with_borrow(r[i], g_negative_p[i], borrow, &r[i], &borrow);
        }
    }
}

/* r = a mod p */
static void sm2_bn_mod_p(uint64_t a[], uint64_t r[])
{
    uint64_t sum_add_to_a0 = 0;
    uint64_t sum_add_to_a1 = 0;
    uint64_t sum_add_to_a2 = 0;
    uint64_t sum_add_to_a3 = 0;
    uint64_t carry = 0;

    /*
     * 1. RDC with 64 bit
     * sum_add_to_a2 = a7 + a7 + a6
     */
    add_with_carry(a[7], a[6], 0, &sum_add_to_a2, &carry);
    sum_add_to_a3 += carry;
    add_with_carry(sum_add_to_a2, a[7], 0, &sum_add_to_a2, &carry);
    sum_add_to_a3 += carry;

    /* sum_add_to_a0 = sum_add_to_a2 + a4 + a5 */
    add_with_carry(sum_add_to_a2, a[4], 0, &sum_add_to_a0, &carry);
    sum_add_to_a1 = sum_add_to_a3 + carry;
    add_with_carry(sum_add_to_a0, a[5], 0, &sum_add_to_a0, &carry);
    sum_add_to_a1 += carry;

    /* add sum_add_to_ai to a[i] */
    add_with_carry(a[0], sum_add_to_a0, 0, &a[0], &carry);
    add_with_carry(a[1], sum_add_to_a1, carry, &a[1], &carry);
    add_with_carry(a[2], sum_add_to_a2, carry, &a[2], &carry);
    /* sum_add_to_a3 =  a[7] */
    add_with_carry(a[3], a[7], carry, &a[3], &carry);
    add_with_carry(a[3], sum_add_to_a3, 0, &a[3], &sum_add_to_a0);
    /* carry to next unit */
    carry += sum_add_to_a0;

    /* 1. RDC with 32 bit, sum_add_to_ai means a[i + 4]'low 32 bits */
    sum_add_to_a0 = get_low_32bits(a[4]);   /* a8 */
    sum_add_to_a1 = get_low_32bits(a[5]);   /* a10 */
    sum_add_to_a2 = get_low_32bits(a[6]);   /* a12 */
    sum_add_to_a3 = get_low_32bits(a[7]);   /* a14 */
    a[4] = get_high_32bits(a[4]);           /* a9 */
    a[5] = get_high_32bits(a[5]);           /* a11 */
    a[6] = get_high_32bits(a[6]);           /* a13 */
    a[7] = get_high_32bits(a[7]);           /* a15 */

    uint64_t sum_tmp1 = sum_add_to_a2 + sum_add_to_a3; /* a12_14 */
    uint64_t sum_tmp2 = sum_add_to_a1 + sum_add_to_a3; /* a10_14 */
    uint64_t sum_tmp3 = a[6] + a[7]; /* a13_15 */
    uint64_t sum_tmp4 = sum_add_to_a0 + a[4]; /* a8_9 */

    a[7] += a[5]; /* a11_15 */
    sum_add_to_a2 = sum_tmp3 + sum_tmp1; /* a12_13_14_15 */
    sum_add_to_a1 += sum_add_to_a2; /* a10_12_13_14_15 */
    sum_add_to_a1 += sum_add_to_a2; /* a10_2*12_2*13_2*14_2*15 */
    sum_add_to_a1 += sum_tmp4; /* a8_9_10_2*12_2*13_2*14_2*15 */
    sum_add_to_a1 += a[5]; /* a8_9_10_11_2*12_2*13_2*14_2*15 */

    sum_add_to_a2 += a[6]; /* a12_2*13_14_15 */
    sum_add_to_a2 += a[5]; /* a11_12_2*13_14_15 */
    sum_add_to_a2 += sum_add_to_a0; /* a8_11_12_2*13_14_15 */

    sum_tmp4 += sum_add_to_a3; /* a8_9_14 */
    sum_tmp4 += a[6]; /* a8_9_13_14 */

    a[4] += sum_tmp3; /* a9_13_15 */

    a[5] += a[4]; /* a9_11_13_15 */
    a[5] += sum_tmp3; /* a9_11_2*13_2*15 */

    sum_tmp1 += sum_tmp2; /* a10_12_2*14 */

    /* from low to high are a[5], sum_tmp1, sum_tmp4, sum_add_to_a2, a[4], sum_tmp2, a[7], sum_add_to_a1 */
    sum_add_to_a0 = sum_tmp1 << 32;
    sum_tmp1 = (sum_tmp1 >> 32) + (sum_add_to_a2 << 32);
    sum_add_to_a2 = (sum_add_to_a2 >> 32) + (sum_tmp2 << 32);
    sum_tmp2 = (sum_tmp2 >> 32) + (sum_add_to_a1 << 32);
    sum_add_to_a1 = sum_add_to_a1 >> 32;

    /* 64bit add */
    uint64_t carry_tmp = 0;

    add_with_carry(a[5], sum_add_to_a0, 0, &a[5], &carry_tmp); /* the first 64bit num */
    add_with_carry(sum_tmp1, 0, carry_tmp, &sum_tmp1, &carry_tmp);
    add_with_carry(a[4], sum_add_to_a2, carry_tmp, &a[4], &carry_tmp);
    add_with_carry(a[7], sum_tmp2, carry_tmp, &a[7], &carry_tmp);
    add_with_carry(carry, sum_add_to_a1, carry_tmp, &carry, &carry_tmp);

    add_with_carry(a[0], a[5], 0, &r[0], &carry_tmp);
    add_with_carry(a[1], sum_tmp1, carry_tmp, &r[1], &carry_tmp);
    add_with_carry(a[2], a[4], carry_tmp, &r[2], &carry_tmp);
    add_with_carry(a[3], a[7], carry_tmp, &r[3], &carry_tmp);
    add_with_carry(carry, 0, carry_tmp, &carry, &carry_tmp);

    sub_with_borrow(r[1], sum_tmp4, 0, &r[1], &carry_tmp); /* carry_tmp means borrow */
    sub_with_borrow(r[2], 0, carry_tmp, &r[2], &carry_tmp);
    sub_with_borrow(r[3], 0, carry_tmp, &r[3], &carry_tmp);
    sub_with_borrow(carry, 0, carry_tmp, &carry, &carry_tmp);

    /* there may be carry, so still need to RDC */
    /* sub carry times p */
    sum_tmp1 = carry;
    sum_tmp2 = sum_tmp1 << 32;
    sum_tmp1 = sum_tmp2 - sum_tmp1;
    add_with_carry(r[0], carry, 0, &r[0], &carry_tmp);
    add_with_carry(r[1], sum_tmp1, carry_tmp, &r[1], &carry_tmp);
    add_with_carry(r[2], 0, carry_tmp, &r[2], &carry_tmp);
    add_with_carry(r[3], sum_tmp2, carry_tmp, &r[3], &carry_tmp);

    if (carry_tmp ==  1) {
        add_with_carry(r[0], g_negative_p[0], 0, &r[0], &carry_tmp);
        add_with_carry(r[1], g_negative_p[1], carry_tmp, &r[1], &carry_tmp);
        add_with_carry(r[2], g_negative_p[2], carry_tmp, &r[2], &carry_tmp);
        add_with_carry(r[3], g_negative_p[3], carry_tmp, &r[3], &carry_tmp);
    }
}

static void sm2_bn_word_mul(uint64_t a, uint64_t b, uint64_t *res_low, uint64_t *res_high)
{
    uint64_t a_h, a_l;
    uint64_t b_h, b_l;
    uint64_t res_h, res_l;
    uint64_t c, t;

    a_h = a >> SM2_SWORD_BIT_SIZE;
    a_l = a & SM2_SWORD_BIT_MASK;
    b_h = b >> SM2_SWORD_BIT_SIZE;
    b_l = b & SM2_SWORD_BIT_MASK;

    res_h = a_h * b_h;
    res_l = a_l * b_l;

    c = a_h * b_l;
    res_h += c >> SM2_SWORD_BIT_SIZE;
    t = res_l;
    res_l += c << SM2_SWORD_BIT_SIZE;
    res_h += t > res_l;

    c = a_l * b_h;
    res_h += c >> SM2_SWORD_BIT_SIZE;
    t = res_l;
    res_l += c << SM2_SWORD_BIT_SIZE;
    res_h += t > res_l;
    *res_high  = res_h;
    *res_low = res_l;
}

/* r = a * b mod p */
static void sm2_bn_mul_mod_p(uint64_t a[], uint64_t b[], uint64_t r[])
{
    uint64_t bn_mul_res[SM2_DATA_MUL_DWORD_SIZE] = { 0 };
    uint64_t bn_mul_res_low = 0;
    uint64_t bn_mul_res_high = 0;
    uint64_t mul_carry = 0;
    uint64_t add_carry = 0;
    uint64_t carry_to_next_unit = 0;

    /* 1. cal a0 * b0 */
    sm2_bn_word_mul(a[0], b[0], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[0] = bn_mul_res_low;
    mul_carry = bn_mul_res_high;

    /* 2. cal a0 * b1, a1 * b0 */
    sm2_bn_word_mul(a[0], b[1], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[1] = bn_mul_res_low;
    add_with_carry(bn_mul_res[1], mul_carry, 0, &bn_mul_res[1], &add_carry);
    mul_carry = bn_mul_res_high + add_carry;

    sm2_bn_word_mul(a[1], b[0], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[1], bn_mul_res_low, 0, &bn_mul_res[1], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &carry_to_next_unit);

    /* 3. cal a0 * b2, a1 * b1, a2 * b0 */
    sm2_bn_word_mul(a[0], b[2], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[2] = bn_mul_res_low;
    add_with_carry(bn_mul_res[2], mul_carry, 0, &bn_mul_res[2], &add_carry);
    add_with_carry(bn_mul_res_high, carry_to_next_unit, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit = add_carry;

    sm2_bn_word_mul(a[1], b[1], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[2], bn_mul_res_low, 0, &bn_mul_res[2], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    sm2_bn_word_mul(a[2], b[0], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[2], bn_mul_res_low, 0, &bn_mul_res[2], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    /* 4. cal a0 * b3, a1 * b2, a2 * b1, a3 * b0 */
    sm2_bn_word_mul(a[0], b[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[3] = bn_mul_res_low;
    add_with_carry(bn_mul_res[3], mul_carry, 0, &bn_mul_res[3], &add_carry);
    add_with_carry(bn_mul_res_high, carry_to_next_unit, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit = add_carry;

    sm2_bn_word_mul(a[1], b[2], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[3], bn_mul_res_low, 0, &bn_mul_res[3], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    sm2_bn_word_mul(a[2], b[1], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[3], bn_mul_res_low, 0, &bn_mul_res[3], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    sm2_bn_word_mul(a[3], b[0], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[3], bn_mul_res_low, 0, &bn_mul_res[3], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    /* 5. cal a1 * b3, a2 * b2, a3 * b1 */
    sm2_bn_word_mul(a[1], b[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[4] = bn_mul_res_low;
    add_with_carry(bn_mul_res[4], mul_carry, 0, &bn_mul_res[4], &add_carry);
    add_with_carry(bn_mul_res_high, carry_to_next_unit, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit = add_carry;

    sm2_bn_word_mul(a[2], b[2], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[4], bn_mul_res_low, 0, &bn_mul_res[4], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    sm2_bn_word_mul(a[3], b[1], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[4], bn_mul_res_low, 0, &bn_mul_res[4], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    /* 6. cal a2 * b3, a3 * b2 */
    sm2_bn_word_mul(a[2], b[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[5] = bn_mul_res_low;
    add_with_carry(bn_mul_res[5], mul_carry, 0, &bn_mul_res[5], &add_carry);
    add_with_carry(bn_mul_res_high, carry_to_next_unit, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit = add_carry;

    sm2_bn_word_mul(a[3], b[2], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_mul_res[5], bn_mul_res_low, 0, &bn_mul_res[5], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    /* 7. cal a3 * a3 */
    sm2_bn_word_mul(a[3], b[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_mul_res[6] = bn_mul_res_low;
    add_with_carry(bn_mul_res[6], mul_carry, 0, &bn_mul_res[6], &add_carry);
    add_with_carry(bn_mul_res_high, carry_to_next_unit, add_carry, &bn_mul_res[7], &add_carry);

    sm2_bn_mod_p(bn_mul_res, r);
}

/* r = a * a mod p */
static void sm2_bn_square_mod_p(uint64_t a[], uint64_t r[])
{
    uint64_t bn_square_res[SM2_DATA_MUL_DWORD_SIZE] = { 0 };
    uint64_t bn_mul_res_low = 0;
    uint64_t bn_mul_res_high = 0;
    uint64_t mul_carry = 0;
    uint64_t add_carry = 0;
    uint64_t carry_to_next_unit = 0;

    /* cal a0 * a1 */
    sm2_bn_word_mul(a[0], a[1], &bn_mul_res_low, &bn_mul_res_high);
    bn_square_res[1] = bn_mul_res_low;
    mul_carry = bn_mul_res_high;

    /* cal a0 * a2 */
    sm2_bn_word_mul(a[0], a[2], &bn_mul_res_low, &bn_mul_res_high);
    bn_square_res[2] = bn_mul_res_low;
    add_with_carry(bn_square_res[2], mul_carry, 0, &bn_square_res[2], &add_carry);
    add_with_carry(bn_mul_res_high, 0, add_carry, &mul_carry, &add_carry);

    /* cal a0 *a3, a1 * a2 */
    sm2_bn_word_mul(a[0], a[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_square_res[3] = bn_mul_res_low;
    add_with_carry(bn_square_res[3], mul_carry, 0, &bn_square_res[3], &add_carry);
    add_with_carry(bn_mul_res_high, 0, add_carry, &mul_carry, &add_carry);

    sm2_bn_word_mul(a[1], a[2], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_square_res[3], bn_mul_res_low, 0, &bn_square_res[3], &add_carry);
    add_with_carry(mul_carry, bn_mul_res_high, add_carry, &mul_carry, &add_carry);
    carry_to_next_unit += add_carry;

    /* cal a1 * a3 */
    sm2_bn_word_mul(a[1], a[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_square_res[4] = bn_mul_res_low;
    add_with_carry(bn_square_res[4], mul_carry, 0, &bn_square_res[4], &add_carry);
    add_with_carry(bn_mul_res_high, carry_to_next_unit, add_carry, &mul_carry, &add_carry);

    /* cal a2 * a3 */
    sm2_bn_word_mul(a[2], a[3], &bn_mul_res_low, &bn_mul_res_high);
    bn_square_res[5] = bn_mul_res_low;
    add_with_carry(bn_square_res[5], mul_carry, 0, &bn_square_res[5], &add_carry);
    add_with_carry(bn_mul_res_high, 0, add_carry, &bn_square_res[6], &bn_square_res[7]);

    /* cal 2 * bn_square_res */
    add_with_carry(bn_square_res[1], bn_square_res[1], 0, &bn_square_res[1], &add_carry);
    add_with_carry(bn_square_res[2], bn_square_res[2], add_carry, &bn_square_res[2], &add_carry);
    add_with_carry(bn_square_res[3], bn_square_res[3], add_carry, &bn_square_res[3], &add_carry);
    add_with_carry(bn_square_res[4], bn_square_res[4], add_carry, &bn_square_res[4], &add_carry);
    add_with_carry(bn_square_res[5], bn_square_res[5], add_carry, &bn_square_res[5], &add_carry);
    add_with_carry(bn_square_res[6], bn_square_res[6], add_carry, &bn_square_res[6], &add_carry);
    add_with_carry(bn_square_res[7], bn_square_res[7], add_carry, &bn_square_res[7], &add_carry);

    /* cal ai ^ 2 */
    sm2_bn_word_mul(a[0], a[0], &bn_mul_res_low, &bn_mul_res_high);
    bn_square_res[0] = bn_mul_res_low;
    mul_carry = bn_mul_res_high;

    sm2_bn_word_mul(a[1], a[1], &bn_mul_res_low, &bn_mul_res_high);
    r[0] = bn_mul_res_low;
    r[1] = bn_mul_res_high;

    sm2_bn_word_mul(a[2], a[2], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_square_res[1], mul_carry, 0, &bn_square_res[1], &add_carry);
    add_with_carry(bn_square_res[2], r[0], add_carry, &bn_square_res[2], &add_carry);
    add_with_carry(bn_square_res[3], r[1], add_carry, &bn_square_res[3], &add_carry);
    add_with_carry(bn_square_res[4], bn_mul_res_low, add_carry, &bn_square_res[4], &add_carry);
    add_with_carry(bn_square_res[5], bn_mul_res_high, add_carry, &bn_square_res[5], &add_carry);
    add_with_carry(bn_square_res[6], 0, add_carry, &bn_square_res[6], &add_carry);
    add_with_carry(bn_square_res[7], 0, add_carry, &bn_square_res[7], &add_carry);

    sm2_bn_word_mul(a[3], a[3], &bn_mul_res_low, &bn_mul_res_high);
    add_with_carry(bn_square_res[6], bn_mul_res_low, 0, &bn_square_res[6], &add_carry);
    add_with_carry(bn_square_res[7], bn_mul_res_high, add_carry, &bn_square_res[7], &add_carry);

    sm2_bn_mod_p(bn_square_res, r);
}

/* check a is valid or not */
int sm2_bn_is_valid(uint64_t a[])
{
    for (uint32_t i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
        if (a[i] != 0)
            return SM2_BN_OK;
    }

    return SM2_BN_INVALID;
}

/*
 * cmp a and b
 * a = b, return 0; a > b, return 1; a < b, return -1
 */
int sm2_bn_cmp(uint64_t a[], uint64_t b[])
{
    uint64_t borrow = 0;
    uint64_t r[SM2_DATA_DWORD_SIZE] = { 0 };

    for (uint32_t i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
        sub_with_borrow(a[i], b[i], borrow, &r[i], &borrow);
    }

    if (borrow == 1)
        return -1;

    if (sm2_bn_is_valid(r) == SM2_BN_INVALID)
        return 0;

    return 1;
}

/* check a in [1, n - 1] */
int sm2_bn_check_indomain_n(uint64_t a[])
{
    int ret;

    ret = sm2_bn_is_valid(a);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_BN_INVALID;

    if (sm2_bn_cmp((uint64_t *)g_n, a) <= 0)
        return SM2_BN_NOT_INDOMAIN;

    return ret;
}

static inline int sm2_bn_is_not_one(uint64_t a[])
{
    return (a[0] != 1 || a[1] != 0 || a[2] != 0 || a[3] != 0);
}

/*
 * a >= b, return 1
 * a < b, return 0
 */
static int sm2_bn_a_is_no_samll_b(uint64_t a[], uint64_t b[])
{
    for (int i = 3; i >= 0; i--) {
        if (a[i] == b[i])
            continue;
        else
            return a[i] > b[i] ? 1 : 0;
    }

    return 1;
}

static int sm2_bn_mod_inv_p(uint64_t a[], uint64_t r[])
{
    uint64_t u[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t x1[SM2_DATA_DWORD_SIZE] = { 1, 0, 0, 0 };
    uint64_t x2[SM2_DATA_DWORD_SIZE] = { 0, 0, 0, 0 };
    uint64_t v[SM2_DATA_DWORD_SIZE] = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000,
                                    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF };
    /* (p + 1) / 2 */
    uint64_t p_add_1_div_2[SM2_DATA_DWORD_SIZE] = {0x8000000000000000, 0xFFFFFFFF80000000,
                                    0xFFFFFFFFFFFFFFFF, 0x7FFFFFFF7FFFFFFF };
    int ret = -1;

    ret = hvb_memcpy_s(u, sizeof(u), a, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    while (sm2_bn_is_not_one(u) && sm2_bn_is_not_one(v)) {
        while (!(u[0] & 1)) {
            shift_right_one_bit(u);
            if (x1[0] & 1) {
                shift_right_one_bit(x1);
                sm2_bn_add_mod_p(x1, p_add_1_div_2, x1);
            } else {
                shift_right_one_bit(x1);
            }
        }

        while (!(v[0] & 1)) {
            shift_right_one_bit(v);
            if (x2[0] & 1) {
                shift_right_one_bit(x2);
                sm2_bn_add_mod_p(x2, p_add_1_div_2, x2);
            } else {
                shift_right_one_bit(x2);
            }
        }

        if (sm2_bn_a_is_no_samll_b(u, v)) {
            sm2_bn_sub_mod_p(u, v, u);
            sm2_bn_sub_mod_p(x1, x2, x1);
        } else {
            sm2_bn_sub_mod_p(v, u, v);
            sm2_bn_sub_mod_p(x2, x1, x2);
        }
    }

    if (sm2_bn_is_not_one(u))
        ret = hvb_memcpy_s(r, SM2_KEY_LEN, x2, SM2_KEY_LEN);
    else
        ret = hvb_memcpy_s(r, SM2_KEY_LEN, x1, SM2_KEY_LEN);

    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    return SM2_BN_OK;
}

/* if a is infinity point, return 1, else return 0. */
static int sm2_is_infinity_point(struct sm2_point_jcb *a)
{
    for (uint32_t i = 0; i < SM2_DATA_DWORD_SIZE; i++) {
        if (a->z[i] != 0)
            return 0;
    }
    return 1;
}

/* set point's z to zero */
static void sm2_set_point_infinity_point(struct sm2_point_jcb *a)
{
    for (uint32_t i = 0; i < SM2_DATA_DWORD_SIZE; i++)
        a->z[i] = 0;
}

/* r = 2 * a */
static void sm2_point_double(struct sm2_point_jcb *a, struct sm2_point_jcb *r)
{
    uint64_t t1[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t t2[SM2_DATA_DWORD_SIZE] = { 0 };

    if (sm2_is_infinity_point(a)) {
        sm2_set_point_infinity_point(r);
        return;
    }

    /* t1 = z ^ 2 */
    sm2_bn_square_mod_p(a->z, t1);

    /* t2 = x - t1 */
    sm2_bn_sub_mod_p(a->x, t1, t2);

    /* t1 = x + t1 */
    sm2_bn_add_mod_p(a->x, t1, t1);

    /* t2 = t1 * t2 */
    sm2_bn_mul_mod_p(t1, t2, t2);

    /* t1 = t2 + t2 */
    sm2_bn_add_mod_p(t2, t2, t1);

    /* t1 = t1 + t2 */
    sm2_bn_add_mod_p(t1, t2, t1);

    /* r.y = a.y + a.y */
    sm2_bn_add_mod_p(a->y, a->y, r->y);

    /* r.z = r.y * a.z */
    sm2_bn_mul_mod_p(r->y, a->z, r->z);

    /* r.y = r.y ^ 2 */
    sm2_bn_square_mod_p(r->y, r->y);

    /* t2 = r.y * a.x */
    sm2_bn_mul_mod_p(r->y, a->x, t2);

    /* r.y = r.y ^ 2 */
    sm2_bn_square_mod_p(r->y, r->y);

    /* r.y = r.y / 2 */
    if (r->y[0] % 2 == 0)
        shift_right_one_bit(r->y);
    else
        add_p_shift_right_one_bit(r->y);

    /* r.x = t1 ^ 2 */
    sm2_bn_square_mod_p(t1, r->x);

    /* r.x -= t2 */
    sm2_bn_sub_mod_p(r->x, t2, r->x);

    /* r.x -= t2 */
    sm2_bn_sub_mod_p(r->x, t2, r->x);

    /* t2 -= r.x */
    sm2_bn_sub_mod_p(t2, r->x, t2);

    /* t1 = t1 * t2 */
    sm2_bn_mul_mod_p(t1, t2, t1);

    /* r.y = t1 - r.y */
    sm2_bn_sub_mod_p(t1, r->y, r->y);

    return;
}

/* r = a + b */
static int sm2_point_add(struct sm2_point_jcb *a, struct sm2_point_jcb *b, struct sm2_point_jcb *r)
{
    uint64_t t1[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t t2[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t t3[SM2_DATA_DWORD_SIZE] = { 0 };
    int ret = -1;

    if (sm2_is_infinity_point(a)) {
        ret = hvb_memcpy_s(r->x, SM2_KEY_LEN, b->x, SM2_KEY_LEN);
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;

        ret = hvb_memcpy_s(r->y, SM2_KEY_LEN, b->y, SM2_KEY_LEN);
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;

        ret = hvb_memcpy_s(r->z, SM2_KEY_LEN, b->z, SM2_KEY_LEN);
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;

        return SM2_BN_OK;
    }

    if (sm2_is_infinity_point(b)) {
        ret = hvb_memcpy_s(r->x, SM2_KEY_LEN, a->x, SM2_KEY_LEN);
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;

        ret = hvb_memcpy_s(r->y, SM2_KEY_LEN, a->y, SM2_KEY_LEN);
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;

        ret = hvb_memcpy_s(r->z, SM2_KEY_LEN, a->z, SM2_KEY_LEN);
        if (hvb_check(ret != 0))
            return SM2_BN_MEMORY_ERR;

        return SM2_BN_OK;
    }

    /* 1) t1 = a.z ^ 2 */
    sm2_bn_square_mod_p(a->z, t1);

    /* 2) t2 = t1 * a.z */
    sm2_bn_mul_mod_p(t1, a->z, t2);

    /* 3) t1 = t1 * b.x check */
    sm2_bn_mul_mod_p(t1, b->x, t1);

    /* 4) t2 = t2 * b.y */
    sm2_bn_mul_mod_p(t2, b->y, t2);

    /* 6) r.y = a.y * b.z */
    sm2_bn_mul_mod_p(a->y, b->z, r->y);

    /* 7) r.z = a.z * b.z */
    sm2_bn_mul_mod_p(a->z, b->z, r->z);

    /* 8) t3 = b.z ^ 2 */
    sm2_bn_square_mod_p(b->z, t3);

    /* 9) r.y = r.y * t3 */
    sm2_bn_mul_mod_p(r->y, t3, r->y);

    /* 10) r.x = a.x * t3 */
    sm2_bn_mul_mod_p(a->x, t3, r->x);

    /* 11) t1 -= r.x */
    sm2_bn_sub_mod_p(t1, r->x, t1);

    /* 12) r.z *= t1 *z1 */
    sm2_bn_mul_mod_p(r->z, t1, r->z);

    /* 13) t2 -= r.y */
    sm2_bn_sub_mod_p(t2, r->y, t2);

    /* 14) t3 = t1 ^ 2 */
    sm2_bn_square_mod_p(t1, t3);

    /* 15) t1 *= t3 */
    sm2_bn_mul_mod_p(t1, t3, t1);

    /* 16) t3 *= r.x */
    sm2_bn_mul_mod_p(t3, r->x, t3);

    /* 17) r.x = t2 ^ 2 */
    sm2_bn_square_mod_p(t2, r->x);

    /* 18) r.x -= t3 */
    sm2_bn_sub_mod_p(r->x, t3, r->x);

    /* 19) r.x -= t3 */
    sm2_bn_sub_mod_p(r->x, t3, r->x);

    /* 20) r.x -= t1 */
    sm2_bn_sub_mod_p(r->x, t1, r->x);

    /* 21) t3 -= r.x */
    sm2_bn_sub_mod_p(t3, r->x, t3);

    /* 22) t3 *= t2 */
    sm2_bn_mul_mod_p(t3, t2, t3);

    /* 23) t1 *= r.y */
    sm2_bn_mul_mod_p(t1, r->y, t1);

    /* 24) r.y = t3 - t1 */
    sm2_bn_sub_mod_p(t3, t1, r->y);

    return SM2_BN_OK;
}

/* convert jcb point to aff point */
static int sm2_point_jcb2aff(const struct sm2_point_jcb *a, struct sm2_point_aff *r)
{
    uint64_t t1[SM2_DATA_DWORD_SIZE] = { 0 };
    uint64_t t2[SM2_DATA_DWORD_SIZE] = { 0 };
    int ret = -1;

    /* t1 = a.z ^ -1 */
    ret = sm2_bn_mod_inv_p((uint64_t *)a->z, t1);
    if (hvb_check(ret != SM2_BN_OK))
        return ret;

    /* t2 = t1 ^ 2 */
    sm2_bn_square_mod_p(t1, t2);

    /* r.x = a.x * t2 */
    sm2_bn_mul_mod_p((uint64_t *)a->x, t2, r->x);

    /* r.y = a.y * t1 * t2 */
    sm2_bn_mul_mod_p((uint64_t *)a->y, t1, r->y);
    sm2_bn_mul_mod_p(r->y, t2, r->y);

    return ret;
}

/* convert aff point to jcb point */
static int sm2_point_aff2jcb(const struct sm2_point_aff *a, struct sm2_point_jcb *r)
{
    int ret = -1;
    ret = hvb_memcpy_s(r->x, SM2_KEY_LEN, a->x, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    ret = hvb_memcpy_s(r->y, SM2_KEY_LEN, a->y, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    ret = hvb_memset_s(r->z, SM2_KEY_LEN, 0, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    r->z[0] = 1;
    return SM2_BN_OK;
}

/* r = -a, jcb point neg same as aff point neg, just neg y */
static int sm2_point_neg(const struct sm2_point_jcb *a, struct sm2_point_jcb *r)
{
    int ret = -1;

    ret = hvb_memcpy_s(r->x, SM2_KEY_LEN, a->x, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    ret = hvb_memcpy_s(r->z, SM2_KEY_LEN, a->z, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    sm2_bn_sub_mod_p((uint64_t *)g_p, (uint64_t *)a->y, r->y);
    return SM2_BN_OK;
}

/* cal p, 3p, 5p ,..., (2^(SLIDING_WINDOW_SIZE-2)-1)p, -p, -3p, -5p ,..., -(2^(SLIDING_WINDOW_SIZE-2)-1)p */
static int sm2_point_pre_cal_table(const struct sm2_point_jcb *p, struct sm2_point_jcb table[])
{
    struct sm2_point_jcb double_p = { 0 };
    uint32_t i;
    int ret = -1;

    ret = hvb_memcpy_s(table[0].x, SM2_KEY_LEN, p->x, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    ret = hvb_memcpy_s(table[0].y, SM2_KEY_LEN, p->y, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    ret = hvb_memcpy_s(table[0].z, SM2_KEY_LEN, p->z, SM2_KEY_LEN);
    if (hvb_check(ret != 0))
        return SM2_BN_MEMORY_ERR;

    sm2_point_double(&table[0], &double_p);
    for (i = 1; i < (SLIDING_WINDOW_PRE_TABLE_SIZE / 2); i++) {
        ret = sm2_point_add(&table[i - 1], &double_p, &table[i]);
        if (hvb_check(ret != SM2_BN_OK))
            return ret;
    }
    for (i = (SLIDING_WINDOW_PRE_TABLE_SIZE / 2); i < SLIDING_WINDOW_PRE_TABLE_SIZE; i++) {
        ret = sm2_point_neg(&table[i - (SLIDING_WINDOW_PRE_TABLE_SIZE / 2)], &table[i]);
        if (hvb_check(ret != SM2_BN_OK))
            return ret;
    }

    return SM2_BN_OK;
}

static uint32_t sm2_bn_get_valid_bits(const uint64_t a[])
{
    uint32_t zero_bits = 0;
    uint64_t mask;

    for (int i = SM2_DATA_DWORD_SIZE - 1; i >= 0; i--) {
        if (a[i] == 0) {
            zero_bits += sizeof(uint64_t) * SM2_BIT_PER_BYTE;
            continue;
        }
        mask = (uint64_t)1 << (sizeof(uint64_t) * SM2_BIT_PER_BYTE - 1);
        while ((a[i] & mask) == 0) {
            zero_bits++;
            mask = mask >> 1;
        }
        break;
    }

    return SM2_DATA_BIT_SIZE - zero_bits;
}

static uint8_t sm2_bn_get_bit_value(const uint64_t a[], uint32_t index)
{
    uint32_t dword_index = index / (sizeof(uint64_t) * SM2_BIT_PER_BYTE);
    uint32_t bit_index = index % (sizeof(uint64_t) * SM2_BIT_PER_BYTE);

    return ((uint8_t)(a[dword_index] >> bit_index)) & 0x1;
}

/* pretable arrangement rule is 1 3 5 7 ... 15 -1 -3 ... -15 */
static int8_t sm2_get_index_in_pretable(int8_t code_num)
{
    int8_t index = (code_num - 1) / 2;
    return code_num < 0 ? (SLIDING_WINDOW_PRE_TABLE_SIZE / 2 - 1 - index) : index;
}

static uint32_t sm2_calculate_window_value(uint32_t cur_bits, uint32_t window_size, const uint64_t k[])
{
    uint32_t dword_index = cur_bits / (sizeof(uint64_t) * SM2_BIT_PER_BYTE);
    uint32_t bit_index = cur_bits % (sizeof(uint64_t) * SM2_BIT_PER_BYTE);
    uint64_t tmp = (1 << window_size) - 1;
    uint32_t code_num_low = (k[dword_index] >> bit_index) & tmp;
    if (bit_index + window_size <= SM2_BIT_PER_LONG || dword_index == SM2_DATA_DWORD_SIZE - 1)
        return code_num_low;
    uint32_t lower_bits = SM2_BIT_PER_LONG - bit_index;
    uint32_t code_num_high = (k[dword_index + 1]  << lower_bits) & tmp;
    return code_num_high + code_num_low;
}

static void sm2_point_scalar_encode(const uint64_t k[], struct sm2_point_scalar_encode_info *encode_info)
{
    uint8_t max_num = (1 << SLIDING_WINDOW_SIZE);
    uint32_t valid_bits = sm2_bn_get_valid_bits(k);
    uint32_t window_offset = -1;
    uint32_t cur_bits = 0;
    uint8_t is_carry = 0;
    uint32_t last_shift_bits = 0;
    while (cur_bits < valid_bits) {
        int8_t encode_num = 0;
        window_offset++;
        while (cur_bits < valid_bits && sm2_bn_get_bit_value(k, cur_bits) == is_carry) {
            cur_bits++;
            last_shift_bits++;
        }

        if (cur_bits < valid_bits)
            encode_num = sm2_calculate_window_value(cur_bits, SLIDING_WINDOW_SIZE, k);

        cur_bits += SLIDING_WINDOW_SIZE;
        encode_num += is_carry;
        is_carry = (encode_num >= (max_num >> 1));
        encode_num = is_carry ? (-(max_num - encode_num)) : encode_num;
        encode_info->code_num[window_offset] = encode_num;
        encode_info->shift_bit[window_offset] = last_shift_bits;
        if (window_offset > 0)
            encode_info->shift_bit[window_offset] += encode_info->shift_bit[window_offset - 1];
        last_shift_bits = (valid_bits > cur_bits) ? SLIDING_WINDOW_SIZE : valid_bits + SLIDING_WINDOW_SIZE - cur_bits;
    }

    if (is_carry) {
        window_offset++;
        encode_info->code_num[window_offset] = 1;
        encode_info->shift_bit[window_offset] = last_shift_bits + encode_info->shift_bit[window_offset - 1];
    }
    encode_info->start_bit = is_carry ? valid_bits : (valid_bits - last_shift_bits);
    encode_info->window_num = window_offset + 1;
}

int sm2_point_mul_add(const uint64_t k1[], const uint64_t k2[], struct sm2_point_aff *p,
                    struct sm2_point_aff *r)
{
    struct sm2_point_jcb p_jcb = { 0 };
    struct sm2_point_jcb r_jcb = { 0 };
    struct sm2_point_jcb precompute_g_table[SLIDING_WINDOW_PRE_TABLE_SIZE] = { 0 };
    struct sm2_point_jcb precompute_p_table[SLIDING_WINDOW_PRE_TABLE_SIZE] = { 0 };
    struct sm2_point_scalar_encode_info k1_encode_info = { 0 };
    struct sm2_point_scalar_encode_info k2_encode_info = { 0 };
    int8_t index = 0;
    int ret = -1;

    ret = sm2_point_aff2jcb(p, &p_jcb);
    if (hvb_check(ret != SM2_BN_OK))
        return ret;

    ret = sm2_point_pre_cal_table(&p_jcb, precompute_p_table);
    if (hvb_check(ret != SM2_BN_OK))
        return ret;

    ret = sm2_point_pre_cal_table(&g_pointg, precompute_g_table);
    if (hvb_check(ret != SM2_BN_OK))
        return ret;

    sm2_point_scalar_encode(k1, &k1_encode_info);
    sm2_point_scalar_encode(k2, &k2_encode_info);

    int start_bit = (k1_encode_info.start_bit > k2_encode_info.start_bit) ?
                            k1_encode_info.start_bit : k2_encode_info.start_bit;

    int32_t k1_window_index =  k1_encode_info.window_num - 1;
    int32_t k2_window_index =  k2_encode_info.window_num - 1;

    while (start_bit > 0) {
        if (k1_window_index >= 0 && start_bit == k1_encode_info.shift_bit[k1_window_index]) {
            index = sm2_get_index_in_pretable(k1_encode_info.code_num[k1_window_index]);
            ret = sm2_point_add(&r_jcb, &precompute_g_table[index], &r_jcb);
            if (hvb_check(ret != SM2_BN_OK))
                return ret;
            k1_window_index--;
        }
        if (k2_window_index >= 0 && start_bit == k2_encode_info.shift_bit[k2_window_index]) {
            index = sm2_get_index_in_pretable(k2_encode_info.code_num[k2_window_index]);
            ret = sm2_point_add(&r_jcb, &precompute_p_table[index], &r_jcb);
            if (hvb_check(ret != SM2_BN_OK))
                return ret;
            k2_window_index--;
        }
        sm2_point_double(&r_jcb, &r_jcb);
        start_bit--;
    }

    if (k1_window_index >= 0 && start_bit == k1_encode_info.shift_bit[k1_window_index]) {
        index = sm2_get_index_in_pretable(k1_encode_info.code_num[k1_window_index]);
        ret = sm2_point_add(&r_jcb, &precompute_g_table[index], &r_jcb);
        if (hvb_check(ret != SM2_BN_OK))
                return ret;
    }
    if (k2_window_index >= 0 && start_bit == k2_encode_info.shift_bit[k2_window_index]) {
        index = sm2_get_index_in_pretable(k2_encode_info.code_num[k2_window_index]);
        ret = sm2_point_add(&r_jcb, &precompute_p_table[index], &r_jcb);
        if (hvb_check(ret != SM2_BN_OK))
                return ret;
    }

    ret = sm2_bn_is_valid(r_jcb.z);
    if (hvb_check(ret != SM2_BN_OK))
        return SM2_BN_INVALID;

    ret = sm2_point_jcb2aff((const struct sm2_point_jcb *)&r_jcb, r);
    if (hvb_check(ret != SM2_BN_OK))
        return ret;

    return ret;
}
