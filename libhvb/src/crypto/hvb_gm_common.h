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
#ifndef __HVB_GM_COMMON_H__
#define __HVB_GM_COMMON_H__

#include <stdint.h>
#include "hvb_gm_log.h"

#ifndef htobe32
#define htobe32(value)                                            \
    ((((value)&0x000000FF) << 24) | (((value)&0x0000FF00) << 8) | (((value)&0x00FF0000) >> 8) | \
        (((value)&0xFF000000) >> 24))
#endif

#ifndef word2byte
#define word2byte(w)              ((w) * sizeof(uint32_t))
#endif

#ifndef byte2bit
#define byte2bit(bytes)     ((bytes) << 3)
#endif

#ifndef u16_inv
#define u16_inv(v)          ((((v) & 0x00FF) << 8) | (((v) & 0xFF00) >> 8))
#endif

#ifndef array_size
#define array_size(x)       (sizeof(x) / sizeof((x)[0]))
#endif

#endif
