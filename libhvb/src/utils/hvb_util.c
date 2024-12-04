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

#define WORD_BYTE_SIZE sizeof(unsigned long)
#define BYTES_PER_TYPE(type) sizeof(type)

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
    uint64_t hex = 0;

    for (int i = BYTES_PER_TYPE(unsigned long) - 1; i >= 0; i--)
        hex |= ((uint64_t)value[i] << ((BYTES_PER_TYPE(unsigned long) - 1 - i) * BYTES_PER_TYPE(unsigned long)));

    return hex;
}

uint64_t hvb_htobe64(uint64_t data)
{
    union {
        uint64_t word;
        uint8_t bytes[BYTES_PER_TYPE(unsigned long)];
    } ret;

    for (int i = BYTES_PER_TYPE(unsigned long) - 1; i >= 0; i--) {
        ret.bytes[i] = (uint8_t)(data & 0xff);
        data >>= BYTES_PER_TYPE(unsigned long);
    }

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

    if (hvb_memset_s(ret, size, 0, size) != 0) {
        hvb_free(ret);
        return NULL;
    }

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

enum hvb_errno check_hvb_ops(struct hvb_ops *ops)
{
    hvb_return_hvb_err_if_null(ops);
    hvb_return_hvb_err_if_null(ops->user_data);
    hvb_return_hvb_err_if_null(ops->read_partition);
    hvb_return_hvb_err_if_null(ops->write_partition);
    hvb_return_hvb_err_if_null(ops->valid_rvt_key);
    hvb_return_hvb_err_if_null(ops->read_rollback);
    hvb_return_hvb_err_if_null(ops->write_rollback);
    hvb_return_hvb_err_if_null(ops->read_lock_state);
    hvb_return_hvb_err_if_null(ops->get_partiton_size);
    return HVB_OK;
}