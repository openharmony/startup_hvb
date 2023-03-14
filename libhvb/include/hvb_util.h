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
#ifndef __HVB_UTIL_H_
#define __HVB_UTIL_H_

#include <stddef.h>
#include "hvb_sysdeps.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_STRING_LEN         17
#define HVB_MAX_DIGITS_UINT64  32

#ifndef NULL
#define NULL 0
#endif

#ifdef offsetof
#define hvb_offsetof(type, member) offsetof(type, member)
#else
#define hvb_offsetof(type, member) ((size_t)&(((type *)0)->member))
#endif

#define hvb_return_hvb_err_if_null(__ptr)                   \
    do {                                                       \
        if ((__ptr) == NULL) {                             \
            hvb_printv("error, %s is NULL\n", #__ptr); \
            return HVB_ERROR_INVALID_ARGUMENT;  \
        }                                                  \
    } while (0)

uint64_t hvb_be64toh(uint64_t data);
uint64_t hvb_htobe64(uint64_t data);

char *hvb_strdup(const char *str);
void *hvb_malloc(uint64_t size);
void *hvb_calloc(uint64_t size);

uint64_t hvb_uint64_to_base10(uint64_t value, char digits[HVB_MAX_DIGITS_UINT64]);
char *hvb_bin2hex(const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif