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
#include "hvb_footer.h"
#include "hvb_util.h"
#include "hvb_cert.h"
#include "hvb_sysdeps.h"

static enum hvb_errno _footer_parser(struct hvb_footer *footer, struct hvb_buf *footer_buf)
{
    uint64_t size;

    if (footer_buf->size < sizeof(*footer)) {
        hvb_print("footer src size error.\n");
        return HVB_ERROR_INVALID_FOOTER_FORMAT;
    }

    hvb_memcpy((uint8_t *)footer, footer_buf->addr, sizeof(*footer));

    /* Check that magic is correct. */
    if (hvb_memcmp(footer->magic, HVB_FOOTER_MAGIC, sizeof(footer->magic)) != 0) {
        hvb_print("Footer magic is incorrect.\n");
        return HVB_ERROR_INVALID_FOOTER_FORMAT;
    }

    /* check these size is correct */
    size = footer->image_size + footer->cert_size + footer_buf->size;
    if (size < footer->image_size || size > footer->partition_size) {
        hvb_print("Invalid image_size in footer.\n");
        return HVB_ERROR_INVALID_FOOTER_FORMAT;
    }

    return HVB_OK;
}

static enum hvb_errno _load_and_parse_footer(struct hvb_ops *ops, struct hvb_footer *footer, const char *ptn)
{
    enum hvb_errno ret = HVB_OK;
    uint64_t read_bytes = 0;
    enum hvb_io_errno io_ret = HVB_IO_OK;
    uint8_t buf[HVB_FOOTER_SIZE] = {0};
    struct hvb_buf footer_buf = {&buf[0], sizeof(buf)};

    io_ret = ops->read_partition(ops, ptn, -HVB_FOOTER_SIZE, HVB_FOOTER_SIZE, footer_buf.addr, &read_bytes);
    if (io_ret != HVB_IO_OK) {
        hvb_printv(ptn, ": error, loading data.\n", NULL);
        return HVB_ERROR_IO;
    }

    if (read_bytes != footer_buf.size) {
        hvb_printv(ptn, ": Read incorrect number of bytes.\n", NULL);
        return HVB_ERROR_IO;
    }

    ret = _footer_parser(footer, &footer_buf);
    if (ret != HVB_OK) {
        hvb_printv(ptn, ": No footer detected,.\n", NULL);
        return ret;
    }

    return HVB_OK;
}

static enum hvb_errno _load_cert(struct hvb_ops *ops, struct hvb_buf *cert, const char *ptn, struct hvb_footer *footer)
{
    enum hvb_io_errno io_ret = HVB_IO_OK;
    uint64_t read_bytes = 0;
    uint64_t offset = footer->cert_offset;

    io_ret = ops->read_partition(ops, ptn, offset, cert->size, cert->addr, &read_bytes);
    if (io_ret != HVB_IO_OK) {
        hvb_printv(ptn, ": error loading signature data.\n", NULL);
        return HVB_ERROR_IO;
    }

    if (cert->size != read_bytes) {
        hvb_printv(ptn, ": Read incorrect number of bytes from.\n", NULL);
        return HVB_ERROR_IO;
    }

    return HVB_OK;
}

enum hvb_errno footer_init_desc(struct hvb_ops *ops, const char *ptn, const char *const *hash_ptn_list,
                                struct hvb_buf *out_pubk, struct hvb_verified_data *vd)
{
    enum hvb_errno ret = HVB_OK;
    struct hvb_buf cert_buf = {NULL, 0};
    struct hvb_footer footer = {0};
    struct hvb_cert_data *cert_info = NULL;

    ret = _load_and_parse_footer(ops, &footer, ptn);
    if (ret != HVB_OK)
        return ret;

    cert_buf.size = footer.cert_size;
    cert_buf.addr = hvb_malloc(cert_buf.size);
    if (!cert_buf.addr) {
        hvb_print("error, alloc cert buf\n");
        return HVB_ERROR_OOM;
    }

    ret = _load_cert(ops, &cert_buf, ptn, &footer);
    if (ret != HVB_OK)
        goto out;

    ret = cert_init_desc(ops, ptn, &cert_buf, hash_ptn_list, out_pubk, vd);
    if (ret != HVB_OK)
        goto out;

    if (vd->num_loaded_certs >= HVB_MAX_NUMBER_OF_LOADED_CERTS) {
        hvb_print("error, too many certs\n");
        ret = HVB_ERROR_OOM;
        goto out;
    }

    cert_info = &vd->certs[vd->num_loaded_certs++];
    cert_info->partition_name = hvb_strdup(ptn);
    cert_info->data = cert_buf;
    cert_info->verify_result = ret;

    return ret;

out:
    if (cert_buf.addr != NULL)
        hvb_free(cert_buf.addr);

    return ret;
}
