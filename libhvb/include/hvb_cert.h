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
#ifndef __HVB_CERT_H_
#define __HVB_CERT_H_

#include "hvb_sysdeps.h"
#include "hvb.h"
#include "hvb_crypto.h"

/* Magic for the vbmeta image header. */
#define HVB_MAGIC                    "HVB"
#define HVB_MAGIC_LEN                4

/* Maximum size of the release string including the terminating NUL byte. */
#define HVB_VERITY_RESERVED_SIZE     36
#define HVB_SIGNATURE_RESERVED_SIZE  64
#define VERITY_NAME_SIZE             64
#define HVB_SIGNATURE_MAX_SIZE       4096

/* The version number of HVB - keep in sync with hvbtool. */
#define HVB_VERSION_MAJOR            1
#define HVB_VERSION_MINOR            0

#define PUBKEY_MODULUS_LEN           256
#define PUBKEY_P_RR_LEN              256
#define SIGNATURE_LEN                256
#define HVB_SIGNATURE_FIXED_SIZE     224

enum hvb_image_type {
    HVB_IMAGE_TYPE_NONE,
    HVB_IMAGE_TYPE_HASH,
    HVB_IMAGE_TYPE_HASHTREE,
    HVB_IMAGE_TYPE_MAX,
};

struct hash_payload {
    uint8_t *salt;
    uint8_t *digest;
} HVB_ATTR_PACKED;

struct hvb_sign_info {
    uint64_t sig_length;
    uint32_t algorithm;
    uint32_t flags;
    uint64_t pubkey_offset;
    uint64_t pubkey_len;
    uint64_t signature_offset;
    uint64_t signature_len;
    uint8_t signature_reserved[HVB_SIGNATURE_RESERVED_SIZE];
    struct hvb_buf pubk;
    struct hvb_buf sign;
} HVB_ATTR_PACKED;

struct hvb_cert {
    /* Three bytes equal to "HVB" (HVB_MAGIC). */
    uint8_t magic[HVB_MAGIC_LEN];

    /* The major version of libhvb. */
    uint32_t version_major;

    /* The minor version of libhvb. */
    uint32_t version_minor;

    /* The release data for verity info data. */
    uint8_t verity_reserved[HVB_VERITY_RESERVED_SIZE];

    /* The original length for image. */
    uint64_t image_original_len;

    /* The length for image after padding zeroes. */
    uint64_t image_len;

    /* The partition name. */
    uint8_t image_name[VERITY_NAME_SIZE];

    /* The location of rollback value. */
    uint64_t rollback_location;

    /* The rollback index. */
    uint64_t rollback_index;

    /*
     * The type of image verity.
     * 1: hash image
     * 2: hashtree image
     */
    uint32_t verity_type;

    /*
     * The algorithm for calculated image hash.
     * 0: ShA256
     * 1: SHA1
     * 2: SHA512
     */
    uint32_t hash_algo;

    /* The offset for salt data, it stored in hash_payload. */
    uint64_t salt_offset;

    /* The size of salt data. */
    uint64_t salt_size;

    /* The offset for digest, it stored in hash_payload. */
    uint64_t digest_offset;

    /* The size of digest. */
    uint64_t digest_size;

    /* The offset for hashtree. */
    uint64_t hashtree_offset;

    /* The size of hashtree. */
    uint64_t hashtree_size;

    /* The size of each block in hashtree mode (4 KB by default). */
    uint64_t data_block_size;

    /* The size of each block for storing hash in a hashtree (4 KB by default). */
    uint64_t hash_block_size;

    /* The device number FEC. */
    uint64_t fec_num_roots;

    /* The offset of FEC. */
    uint64_t fec_offset;

    /* The size of FEC. */
    uint64_t fec_size;

    /* save the salt and digest of image. */
    struct hash_payload hash_payload;

    /* signature info */
    struct hvb_sign_info signature_info;
} HVB_ATTR_PACKED;

enum hvb_errno cert_init_desc(struct hvb_ops *ops, const char *ptn, struct hvb_buf *cert_buf,
                              const char *const *hash_ptn_list, struct hvb_buf *out_pubk,
                              struct hvb_verified_data *verified_data);
enum hvb_errno hvb_cert_parser(struct hvb_cert *cert, struct hvb_buf *cert_buf);

#endif
