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
#ifndef __HVB_OPS_H_
#define __HVB_OPS_H_
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum hvb_io_errno {
    HVB_IO_OK,
    HVB_IO_ERROR_OOM,
    HVB_IO_ERROR_IO,
    HVB_IO_ERROR_NO_SUCH_PARTITION,
    HVB_IO_ERROR_RANGE_OUTSIDE_PARTITION,
    HVB_IO_ERROR_NO_SUCH_VALUE,
    HVB_IO_ERROR_INVALID_VALUE_SIZE,
    HVB_IO_ERROR_INSUFFICIENT_SPACE,
};

struct hvb_ops {
    const void *user_data;
    enum hvb_io_errno (*read_partition)(struct hvb_ops *ops, const char *ptn, int64_t offset,
                        uint64_t num_bytes, void *buffer, uint64_t *out_num_read);
    enum hvb_io_errno (*write_partition)(struct hvb_ops *ops, const char *ptn, int64_t offset,
                         uint64_t num_bytes, const void *buffer);
    enum hvb_io_errno (*valid_rvt_key)(struct hvb_ops *ops, const uint8_t *pubkey,
                       uint64_t pubkey_length, const uint8_t *pubkey_metadata,
                       uint64_t pubkey_metadata_length, bool *out_is_trusted);
    enum hvb_io_errno (*read_rollback)(struct hvb_ops *ops,
                       uint64_t rollback_index_location,
                       uint64_t *out_rollback_index);
    enum hvb_io_errno (*write_rollback)(struct hvb_ops *ops, uint64_t rollback_index_location,
                        uint64_t rollback_index);
    enum hvb_io_errno (*read_lock_state)(struct hvb_ops *ops, bool *lock_state);
    enum hvb_io_errno (*get_partiton_size)(struct hvb_ops *ops, const char *ptn, uint64_t *out_bytes);
};

#ifdef __cplusplus
}
#endif

#endif