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
#ifndef __HVB_H_
#define __HVB_H_

#include "hvb_ops.h"
#include "hvb_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define HVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS 32
#define HVB_MAX_NUMBER_OF_LOADED_CERTS             32
#define HVB_MAX_NUMBER_OF_LOADED_IMAGES            32

/* Maximum size of a rvt image - 64 KiB. */
#define RVT_MAX_SIZE (64 * 1024)

/* Maximum size for hash parttion list, one is RVT and the other for null pointer. */
#define REQUEST_LIST_LEN 2

enum hvb_errno {
    HVB_OK,
    HVB_ERROR_OOM,
    HVB_ERROR_IO,
    HVB_ERROR_VERIFY_SIGN,
    HVB_ERROR_VERIFY_HASH,
    HVB_ERROR_ROLLBACK_INDEX,
    HVB_ERROR_PUBLIC_KEY_REJECTED,
    HVB_ERROR_INVALID_CERT_FORMAT,
    HVB_ERROR_INVALID_FOOTER_FORMAT,
    HVB_ERROR_UNSUPPORTED_VERSION,
    HVB_ERROR_INVALID_ARGUMENT,
};

struct hvb_image_data {
    char *partition_name;
    struct hvb_buf data;
    bool preloaded;
};

struct hvb_cert_data {
    char *partition_name;
    struct hvb_buf data;
    enum hvb_errno verify_result;
};

struct hvb_cmdline_data {
    char *buf;
    uint64_t cur_pos; // the first avaliable pos in buf
    uint64_t max_size;
};

struct hvb_verified_data {
    struct hvb_cert_data *certs;
    uint64_t num_loaded_certs;
    struct hvb_image_data *images;
    uint64_t num_loaded_images;
    struct hvb_cmdline_data cmdline;
    uint64_t rollback_indexes[HVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS];
};

enum hvb_errno hvb_chain_verify(struct hvb_ops *ops, const char *rvt_parttion_name,
                                const char *const *hash_ptn_list,
                                struct hvb_verified_data **out_data);
void hvb_chain_verify_data_free(struct hvb_verified_data *verified_data);

#ifdef __cplusplus
}
#endif

#endif
