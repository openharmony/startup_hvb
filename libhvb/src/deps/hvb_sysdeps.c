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
#include "hvb_sysdeps.h"
#include <string.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "libhvb"

int hvb_memcmp(const void *src1, const void *src2, size_t n)
{
    return memcmp(src1, src2, n);
}

void *hvb_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

void *hvb_memset(void *dest, const int c, size_t n)
{
    return memset(dest, c, n);
}

int hvb_strcmp(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

int hvb_strncmp(const char *s1, const char *s2, size_t n)
{
    return strncmp(s1, s2, n);
}

size_t hvb_strlen(const char *str)
{
    return (size_t)strlen(str);
}

void hvb_abort(void)
{
    printf("ERROR, an error happened\n");
}

void hvb_print(const char *message)
{
    printf("%s\n", message);
}

void hvb_printv(const char *message, ...)
{
    va_list ap;
    const char *msg;

    va_start(ap, message);
    for (msg = message; msg != NULL; msg = va_arg(ap, const char*)) {
        printf("%s", msg);
    }
    va_end(ap);
}

void *hvb_malloc_(size_t size)
{
    return malloc(size);
}

void hvb_free(void *ptr)
{
    free(ptr);
}

uint32_t hvb_div_by_10(uint64_t *dividend)
{
    uint32_t rem = (uint32_t)(*dividend % 10);
    *dividend /= 10;
    return rem;
}
