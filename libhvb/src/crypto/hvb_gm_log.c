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
#include "hvb_gm_log.h"
#include "hvb_sysdeps.h"
#include "hvb_util.h"
#include <stdio.h>

#ifdef HVB_CRYPTO_DEBUG
uint32_t hvb_check_log(uint32_t matched, const char *pfunc, uint32_t line)
{
    if (matched) {
        hvb_printv("function =", pfunc, "line = ", NULL);
        hvb_print_u64(line);
    }
    return matched;
}
#endif
