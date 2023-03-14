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
#ifndef __HVB_CMDLINE_H_
#define __HVB_CMDLINE_H_

#include "hvb_ops.h"
#include "hvb.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CMD_LINE_SIZE (4096UL)

#define HVB_CMDLINE_VB_STATE       "ohos.boot.hvb.enable"
#define HVB_CMDLINE_HASH_ALG       "ohos.boot.hvb.hash_algo"
#define HVB_CMDLINE_CERT_DIGEST    "ohos.boot.hvb.digest"
#define HVB_CMDLINE_RVT_SIZE       "ohos.boot.hvb.size"
#define HVB_CMDLINE_VERSION        "ohos.boot.hvb.version"
#define HVB_CMDLINE_DEV_STATE      "ohos.boot.hvb.device_state"

enum hvb_errno hvb_creat_cmdline(struct hvb_ops *ops, struct hvb_verified_data *vd);

#ifdef __cplusplus
}
#endif

#endif