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
#include "hvb_util.h"
#include "hvb_types.h"

char *hvb_bin2hex(const uint8_t *value, size_t len)
{
    const char digits[MAX_STRING_LEN] = "0123456789abcdef";
    char *hex;
    size_t n;

    hex = hvb_malloc(len * 2 + 1);
    if (hex == NULL)
        return NULL;

    for (n = 0; n < len; n++) {
        hex[n * 2] = digits[value[n] >> 4];
        hex[n * 2 + 1] = digits[value[n] & 0x0f];
    }
    hex[n * 2] = '\0';

    return hex;
}

uint64_t hvb_uint64_to_base10(uint64_t value, char digits[HVB_MAX_DIGITS_UINT64])
{
    char rev_digits[HVB_MAX_DIGITS_UINT64];
    uint64_t n, num_digits;

    for (num_digits = 0; num_digits < HVB_MAX_DIGITS_UINT64 - 1;) {
        rev_digits[num_digits++] = hvb_div_by_10(&value) + '0';
        if (value == 0) {
            break;
        }
    }

    for (n = 0; n < num_digits; n++)
        digits[n] = rev_digits[num_digits - 1 - n];
    digits[n] = '\0';

    return n;
}


uint64_t hvb_be64toh(uint64_t data)
{
    uint8_t *value = (uint8_t *)&data;
    uint64_t hex;

    hex = ((uint64_t)value[0]) << 56;
    hex |= ((uint64_t)value[1]) << 48;
    hex |= ((uint64_t)value[2]) << 40;
    hex |= ((uint64_t)value[3]) << 32;
    hex |= ((uint64_t)value[4]) << 24;
    hex |= ((uint64_t)value[5]) << 16;
    hex |= ((uint64_t)value[6]) << 8;
    hex |= ((uint64_t)value[7]);
    return hex;
}

uint64_t hvb_htobe64(uint64_t data)
{
    union {
        uint64_t word;
        uint8_t bytes[8];
    } ret;

    ret.bytes[0] = (data >> 56) & 0xff;
    ret.bytes[1] = (data >> 48) & 0xff;
    ret.bytes[2] = (data >> 40) & 0xff;
    ret.bytes[3] = (data >> 32) & 0xff;
    ret.bytes[4] = (data >> 24) & 0xff;
    ret.bytes[5] = (data >> 16) & 0xff;
    ret.bytes[6] = (data >> 8) & 0xff;
    ret.bytes[7] = data & 0xff;
    return ret.word;
}

void *hvb_malloc(uint64_t size)
{
    void *ret = hvb_malloc_(size);

    if (!ret) {
        hvb_print("Failed to allocate memory.\n");
        return NULL;
    }
    return ret;
}

void *hvb_calloc(uint64_t size)
{
    void *ret = hvb_malloc(size);

    if (!ret)
        return NULL;

    hvb_memset(ret, 0, size);

    return ret;
}

char *hvb_strdup(const char *str)
{
    size_t len = hvb_strlen(str);
    char *new_str = hvb_malloc(len + 1);

    if (!new_str)
        return NULL;

    hvb_memcpy(new_str, str, len);

    new_str[len] = '\0';

    return new_str;
}
