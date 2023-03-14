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
#ifndef __HVB_RVT_H_
#define __HVB_RVT_H_

#include "hvb_cert.h"
#include "hvb_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic for the rvt image header. */
#define RVT_MAGIC                    "rot"
#define RVT_MAGIC_LEN                4
#define RVT_RELEASE_SIZE             64
#define MAX_NUMBER_OF_RVT_IMAGES     32
#define PUBKEY_LEN                   528
#define PARTITION_NAME_LEN           64

/* Maximum size of a rvt image - 64 KiB. */
#define RVT_MAX_SIZE                 (64 * 1024)

struct rvt_pubk_desc {
    /* The partition name of verity image. */
    char name[PARTITION_NAME_LEN];

    /* Offset into the rvt_payload of pubkey from verity image. */
    uint64_t pubkey_offset;

    /* Length of the public key. */
    uint64_t pubkey_len;

    /* pubkey_payload. */
    uint8_t pubkey_payload[PUBKEY_LEN];
} HVB_ATTR_PACKED;

struct rvt_image_header {
    /* Four bytes equal to "rot" (magic). */
    uint8_t magic[RVT_MAGIC_LEN];

    /* The verity_num. */
    uint32_t verity_num;

    /* The reserved data, must be 0. */
    uint8_t rvt_reserved[RVT_RELEASE_SIZE];
} HVB_ATTR_PACKED;

enum hvb_errno hvb_rvt_head_parser(const struct hvb_buf *rvt, struct rvt_image_header *dest);
enum hvb_errno hvb_rvt_get_pubk_desc(const struct hvb_buf *rvt, struct hvb_buf *pubk_desc);
enum hvb_errno hvb_rvt_pubk_desc_parser(const struct hvb_buf *pubk, struct rvt_pubk_desc *desc);
enum hvb_errno hvb_rvt_get_pubk_buf(struct hvb_buf *key_buf, const struct hvb_buf *rvt, struct rvt_pubk_desc *desc);
enum hvb_errno hvb_calculate_certs_digest(struct hvb_verified_data *vd, uint8_t *out_digest);

#ifdef __cplusplus
}
#endif

#endif /* HVB_RVT_H_ */
