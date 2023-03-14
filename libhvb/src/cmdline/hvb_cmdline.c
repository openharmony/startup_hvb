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
#include "hvb_cmdline.h"
#include "hvb_util.h"
#include "hvb_cert.h"
#include "hvb_rvt.h"
#include "hvb_ops.h"
#include "hvb.h"
#include "hvb_sysdeps.h"
#include "hvb_crypto.h"

static int cmdline_append_option(struct hvb_verified_data *vd, const char *key, const char *value)
{
    uint64_t option_len = 0;
    uint64_t key_len, value_len;
    struct hvb_cmdline_data *cmdline = NULL;

    if (vd == NULL || vd->cmdline.buf == NULL)
        return -1;

    cmdline = &vd->cmdline;

    key_len = hvb_strlen(key);
    value_len = hvb_strlen(value);
    /* 2 for blank space and = */
    option_len = key_len + value_len + 2;
    if (option_len > cmdline->max_size - cmdline->cur_pos - 1)
        return -1;

    /* append blank space */
    cmdline->buf[cmdline->cur_pos] = ' ';
    cmdline->cur_pos++;
    /* append key */
    hvb_memcpy(cmdline->buf + cmdline->cur_pos, key, key_len);
    cmdline->cur_pos += key_len;
    /* append = */
    cmdline->buf[cmdline->cur_pos] = '=';
    cmdline->cur_pos++;
    /* append value */
    hvb_memcpy(cmdline->buf + cmdline->cur_pos, value, value_len);
    cmdline->cur_pos += value_len;

    return 1;
}

static int hvb_append_version_cmdline(struct hvb_verified_data *vd, const char *key_value,
                                      uint64_t version_major, uint64_t version_minor)
{
    char major_digits[HVB_MAX_DIGITS_UINT64];
    char minor_digits[HVB_MAX_DIGITS_UINT64];
    char combined[HVB_MAX_DIGITS_UINT64 * 2 + 1];
    uint64_t num_major_digits, num_minor_digits;

    num_major_digits = hvb_uint64_to_base10(version_major, major_digits);
    num_minor_digits = hvb_uint64_to_base10(version_minor, minor_digits);

    hvb_memcpy(combined, major_digits, num_major_digits);
    combined[num_major_digits] = '.';
    hvb_memcpy(combined + num_major_digits + 1, minor_digits, num_minor_digits);
    combined[num_major_digits + 1 + num_minor_digits] = '\0';

    return cmdline_append_option(vd, key_value, combined);
}

static int cmdline_append_uint64_base10(struct hvb_verified_data *vd, const char *key, uint64_t value)
{
    char digits[HVB_MAX_DIGITS_UINT64];

    hvb_uint64_to_base10(value, digits);

    return cmdline_append_option(vd, key, digits);
}

static int cmdline_append_hex(struct hvb_verified_data *vd, const char* key,
                              const uint8_t *data, uint64_t data_len)
{
    int ret;
    char *hex_data = hvb_bin2hex(data, data_len);

    if (hex_data == NULL) {
        return 0;
    }

    ret = cmdline_append_option(vd, key, hex_data);
    hvb_free(hex_data);

    return ret;
}

enum hvb_errno hvb_creat_cmdline(struct hvb_ops *ops, struct hvb_verified_data *vd)
{
    enum hvb_errno ret = HVB_OK;
    enum hvb_io_errno io_ret = HVB_IO_OK;
    bool device_locked = false;

    /* set ohos.boot.hvb.version. */
    if (!hvb_append_version_cmdline(vd, HVB_CMDLINE_VERSION,
                                    HVB_VERSION_MAJOR, HVB_VERSION_MINOR)) {
        ret = HVB_ERROR_OOM;
        goto fail;
    }

    /* set ohos.boot.device_state to "locked" or "unlocked". */
    io_ret = ops->read_lock_state(ops, &device_locked);
    if (io_ret == HVB_IO_ERROR_OOM) {
        ret = HVB_ERROR_OOM;
        goto fail;
    } else if (io_ret != HVB_IO_OK) {
        hvb_print("Error getting device state.\n");
        ret = HVB_ERROR_IO;
        goto fail;
    }

    if (!cmdline_append_option(vd, HVB_CMDLINE_DEV_STATE,
                               device_locked ? "locked" : "unlocked")) {
        ret = HVB_ERROR_OOM;
        goto fail;
    }

    /*
     * set ohos.boot.hvb.{hash_algo, size, digest} - use same hash
     * function as is used to sign rvt.
     */
    uint8_t rvt_digest[HVB_SHA256_DIGEST_BYTES] = {0};
    uint64_t rvt_size = 0;
    for (uint64_t n = 0; n < vd->num_loaded_certs; n++) {
        rvt_size += vd->certs[n].data.size;
    }

    if (hvb_calculate_certs_digest(vd, rvt_digest) != HVB_OK) {
        hvb_print("Error calculate rvt digest.\n");
        ret = HVB_ERROR_OOM;
        goto fail;
    }

    if (!cmdline_append_option(vd, HVB_CMDLINE_HASH_ALG, "sha256") ||
        !cmdline_append_uint64_base10(vd, HVB_CMDLINE_RVT_SIZE, rvt_size) ||
        !cmdline_append_hex(vd, HVB_CMDLINE_CERT_DIGEST, rvt_digest, HVB_SHA256_DIGEST_BYTES)) {
        ret = HVB_ERROR_OOM;
        goto fail;
    }

fail:
    return ret;
}
