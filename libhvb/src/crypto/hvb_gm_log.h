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
#ifndef __HVB_GM_LOG_H__
#define __HVB_GM_LOG_H__

#include <stdint.h>

#if !defined(HVB_CRYPTO_DEBUG)
#define hvb_check(express) (express)
#else
uint32_t hvb_check_log(uint32_t matched, const char *pfunc, uint32_t line);
#define hvb_check(express) (hvb_check_log((express) ? 1 : 0, __func__, __LINE__) != 0)
#endif

#endif
