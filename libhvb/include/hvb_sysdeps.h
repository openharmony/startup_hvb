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
#ifndef __HVB_SYSDEPS_H_
#define __HVB_SYSDEPS_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HVB_ATTR_PACKED __attribute__((packed))

int hvb_memcmp(const void *src1, const void *src2, size_t n);
int hvb_strcmp(const char *s1, const char *s2);
int hvb_strncmp(const char *s1, const char *s2, size_t n);
void *hvb_memcpy(void *dest, const void *src, size_t n);
void *hvb_memset(void *dest, const int c, size_t n);
void hvb_print(const char *message);
void hvb_printv(const char *message, ...);
void *hvb_malloc_(size_t size);
void hvb_free(void *ptr);
void hvb_abort(void);
size_t hvb_strlen(const char *str);
uint32_t hvb_div_by_10(uint64_t *dividend);

#ifdef __cplusplus
}
#endif

#endif /* __HVB_SYSDEPS_H_ */
