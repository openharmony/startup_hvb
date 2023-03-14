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
#ifndef __HVB_FOOTER_H_
#define __HVB_FOOTER_H_

#include "hvb_sysdeps.h"
#include "hvb_types.h"
#include "hvb_ops.h"
#include "hvb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic for the footer. */
#define HVB_FOOTER_MAGIC       "HVB"
#define HVB_FOOTER_MAGIC_LEN   4
/* Size of the footer. */
#define HVB_FOOTER_SIZE        104

struct hvb_footer {
    uint8_t magic[HVB_FOOTER_MAGIC_LEN];
    uint64_t cert_offset;
    uint64_t cert_size;
    uint64_t image_size;
    uint64_t partition_size;
    uint8_t reserved[64];
};

enum hvb_errno footer_init_desc(struct hvb_ops *ops, const char *ptn, const char *const *hash_ptn_list,
                                struct hvb_buf *out_pubk, struct hvb_verified_data *vd);

#ifdef __cplusplus
}
#endif

#endif /* HVB_FOOTER_H_ */
