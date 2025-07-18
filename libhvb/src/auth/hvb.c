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
#include <stdio.h>
#include <stdlib.h>
#include "hvb_footer.h"
#include "hvb_crypto.h"
#include "hvb_ops.h"
#include "hvb_rvt.h"
#include "hvb_cert.h"
#include "hvb_sysdeps.h"
#include "hvb_util.h"
#include "hvb_cmdline.h"
#include "hvb.h"

struct hvb_verified_data *hvb_init_verified_data(void)
{
    struct hvb_verified_data *vd = NULL;

    vd = hvb_calloc(sizeof(*vd));
    if (!vd) {
        hvb_print("malloc verified_data fail\n");
        return NULL;
    }

    vd->certs = hvb_calloc(sizeof(struct hvb_cert_data) * HVB_MAX_NUMBER_OF_LOADED_CERTS);
    if (!vd->certs) {
        hvb_print("malloc certs fail\n");
        goto fail;
    }

    vd->images = hvb_calloc(sizeof(struct hvb_image_data) * HVB_MAX_NUMBER_OF_LOADED_IMAGES);
    if (!vd->images) {
        hvb_print("malloc images fail\n");
        goto fail;
    }

    vd->num_loaded_certs = 0;
    vd->num_loaded_images = 0;

    vd->cmdline.buf = hvb_calloc(CMD_LINE_SIZE);
    if (!vd->cmdline.buf) {
        hvb_print("malloc cmdline fail\n");
        goto fail;
    }

    vd->cmdline.cur_pos = 0;
    vd->cmdline.max_size = CMD_LINE_SIZE;
    vd->algorithm = 0;
    vd->match_backup_pubkey = 0;

    return vd;

fail:
    hvb_chain_verify_data_free(vd);
    hvb_free(vd);
    vd = NULL;
    return vd;
}

static enum hvb_errno hvb_rvt_verify_root(struct hvb_ops *ops, const char *ptn,
                                          const char *const *ptn_list,
                                          struct hvb_verified_data *vd)
{
    enum hvb_errno ret = HVB_OK;
    enum hvb_io_errno io_ret = HVB_IO_OK;
    bool is_trusted = false;
    struct hvb_buf cert_pubk = {0};

    ret = footer_init_desc(ops, ptn, ptn_list, &cert_pubk, vd);
    if (ret != HVB_OK) {
        hvb_printv("error verity partition: ", ptn, "\n", NULL);
        goto fail;
    }

    io_ret = ops->valid_rvt_key(ops, cert_pubk.addr, cert_pubk.size, NULL, 0, &is_trusted);
    if (io_ret != HVB_IO_OK) {
        ret = HVB_ERROR_PUBLIC_KEY_REJECTED;
        hvb_print("error, rvt public key invalid\n");
        goto fail;
    }

    if (is_trusted == false) {
        ret = HVB_ERROR_PUBLIC_KEY_REJECTED;
        hvb_print("error, rvt public key rejected\n");
        goto fail;
    }

fail:
    return ret;
}

static struct hvb_buf *hvb_get_partition_image(struct hvb_verified_data *vd, const char *ptn)
{
    struct hvb_image_data *p = vd->images;
    struct hvb_image_data *end = p + vd->num_loaded_images;
    size_t name_len = hvb_strnlen(ptn, HVB_MAX_PARTITION_NAME_LEN);
    if (name_len >= HVB_MAX_PARTITION_NAME_LEN) {
        hvb_print("invalid ptn name len\n");
        return NULL;
    }

    for (; p < end; p++) {
        if (hvb_strnlen(p->partition_name, HVB_MAX_PARTITION_NAME_LEN) == name_len &&
            hvb_strncmp(ptn, p->partition_name, HVB_MAX_PARTITION_NAME_LEN) == 0) {
            return &p->data;
        }
    }

    return NULL;
}

static bool hvb_buf_equal(const struct hvb_buf *buf1, const struct hvb_buf *buf2)
{
    return buf1->size == buf2->size && hvb_memcmp(buf1->addr, buf2->addr, buf1->size) == 0;
}

static enum hvb_errno get_desc_size(uint32_t algo, uint32_t pubkey_num_per_ptn, uint64_t *desc_size)
{
    uint64_t key_len = 0;
    switch (algo) {
        case 1: { // SHA256_RSA4096
            key_len = PUBKEY_LEN_4096;
            break;
        }
        case 2: { // SHA256_RSA2048
            key_len = PUBKEY_LEN_2048;
            break;
        }
        case 3: { // SM3
            key_len = PUBKEY_LEN_SM;
            break;
        }
        default: {
            hvb_print("hash algo dsnt support\n");
            return HVB_ERROR_INVALID_ARGUMENT;
        }
    }

    /* actual desc size is const part + pubkey payload part */
    *desc_size = hvb_offsetof(struct rvt_pubk_desc, pubkey_payload) + key_len * pubkey_num_per_ptn;

    return HVB_OK;
}

static enum hvb_errno hvb_rvt_parser(const struct hvb_buf *rvt, const struct hvb_verified_data *vd,
                                     struct rvt_image_header *header, struct hvb_buf *pubk_descs, uint64_t *desc_size)
{
    enum hvb_errno ret;
    uint64_t rvt_real_size;
    uint32_t pubkey_num_per_ptn;

    ret = hvb_rvt_head_parser(rvt, header);
    if (ret != HVB_OK) {
        hvb_print("error, parse rvt header.\n");
        return ret;
    }

    if (header->pubkey_num_per_ptn == 0) {
        hvb_print("old version rvt, use default pubkey num.\n");
        pubkey_num_per_ptn = 1;
    } else {
        pubkey_num_per_ptn = header->pubkey_num_per_ptn;
    }

    ret = get_desc_size(vd->algorithm, pubkey_num_per_ptn, desc_size);
    if (ret != HVB_OK) {
        hvb_print("error, get desc size.\n");
        return ret;
    }

    rvt_real_size = sizeof(*header) + header->verity_num * (*desc_size);
    if (rvt_real_size > rvt->size || rvt_real_size < sizeof(*header)) {
        hvb_print("error, rvt_real_size is invalid.\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    ret = hvb_rvt_get_pubk_desc(rvt, pubk_descs);
    if (ret != HVB_OK) {
        hvb_print("error, pubk descs.\n");
        return ret;
    }

    return HVB_OK;
}

static enum hvb_errno hvb_pubkey_parser(const struct hvb_buf *rvt, uint32_t pubkey_num_per_ptn,
                                        struct rvt_pubk_desc *desc)
{
    enum hvb_errno ret;

    ret = hvb_rvt_get_pubk_buf(&desc->pubkey_payload, rvt, desc->pubkey_offset, desc->pubkey_len);
    if (ret != HVB_OK) {
        hvb_print("errror, get main pubk buf\n");
        return ret;
    }

    if (pubkey_num_per_ptn == RVT_MAX_VALID_KEY_NUM) {
        ret = hvb_rvt_get_pubk_buf(&desc->pubkey_payload_backup, rvt,
                                   desc->pubkey_offset + desc->pubkey_len, desc->pubkey_len);
        if (ret != HVB_OK) {
            hvb_print("errror, get backup pubk buf\n");
            return ret;
        }
    }

    return HVB_OK;
}

static enum hvb_errno hvb_walk_verify_nodes(struct hvb_ops *ops, const char *const *ptn_list,
                                            struct hvb_buf *rvt, struct hvb_verified_data *vd)
{
    enum hvb_errno ret = HVB_OK;
    uint32_t i;
    struct hvb_buf pubk_descs = {0};
    struct rvt_pubk_desc desc = {0};
    struct hvb_buf cert_pubk = {0};
    struct rvt_image_header header = {0};
    uint64_t desc_size;
    bool is_locked;

    if (ops->read_lock_state(ops, &is_locked) != HVB_IO_OK) {
        ret = HVB_ERROR_IO;
        hvb_print("error, get lock state.\n");
        goto fail;
    }

    ret = hvb_rvt_parser(rvt, vd, &header, &pubk_descs, &desc_size);
    if (ret != HVB_OK) {
        hvb_print("error, parse rvt.\n");
        goto fail;
    }

    for (i = 0; i < header.verity_num; i++) {
        ret = hvb_rvt_pubk_desc_parser(&pubk_descs, &desc);
        if (ret != HVB_OK) {
            hvb_print("errror, parser rvt pubkey descs\n");
            goto fail;
        }

        ret = hvb_pubkey_parser(rvt, header.pubkey_num_per_ptn, &desc);
        if (ret != HVB_OK) {
            hvb_print("errror, parse pubkey\n");
            goto fail;
        }

        ret = footer_init_desc(ops, &desc.name[0], ptn_list, &cert_pubk, vd);
        if (ret != HVB_OK) {
            hvb_printv("error, verity partition: ", desc.name, "\n", NULL);
            goto fail;
        }

        if (hvb_buf_equal(&desc.pubkey_payload, &cert_pubk) != true) {
            if (!is_locked && header.pubkey_num_per_ptn == RVT_MAX_VALID_KEY_NUM &&
                hvb_buf_equal(&desc.pubkey_payload_backup, &cert_pubk)) {
                hvb_printv(desc.name, "backup pubkey verified\n", NULL);
                vd->match_backup_pubkey = 1;
            } else {
                ret = HVB_ERROR_PUBLIC_KEY_REJECTED;
                hvb_printv("error, compare public key: ", desc.name, "\n", NULL);
                goto fail;
            }
        }

        pubk_descs.addr += desc_size;
    }

fail:
    return ret;
}

static char const **hash_ptn_list_add_rvt(const char *const *hash_ptn_list, const char *rvt_ptn)
{
    size_t n;
    bool need_add_rvt = true;
    char const **ptn = NULL;
    size_t num_parttions = 0;

    if (hash_ptn_list != NULL) {
        while (hash_ptn_list[num_parttions] != NULL) {
            num_parttions++;
        }
    }

    num_parttions += REQUEST_LIST_LEN;

    ptn = (char const **)hvb_calloc(num_parttions * sizeof(char *));
    if (ptn == NULL) {
        hvb_print("error, alloc ptn\n");
        return NULL;
    }

    for (n = 0; n < num_parttions - REQUEST_LIST_LEN; n++) {
        ptn[n] = hash_ptn_list[n];
        if (hvb_strncmp(ptn[n], rvt_ptn, HVB_MAX_PARTITION_NAME_LEN) == 0) {
            need_add_rvt = false;
        }
    }

    if (need_add_rvt) {
        ptn[num_parttions - REQUEST_LIST_LEN] = rvt_ptn;
    }

    return ptn;
}

enum hvb_errno hvb_chain_verify(struct hvb_ops *ops,
                                const char *rvt_ptn,
                                const char *const *hash_ptn_list,
                                struct hvb_verified_data **out_vd)
{
    enum hvb_errno ret = HVB_OK;
    struct hvb_buf *rvt_image = NULL;
    struct hvb_verified_data *vd = NULL;
    char const **ptn_list = NULL;

    hvb_return_hvb_err_if_null(ops);
    hvb_return_hvb_err_if_null(rvt_ptn);
    hvb_return_hvb_err_if_null(out_vd);
    ret = check_hvb_ops(ops);
    if (ret != HVB_OK) {
        hvb_print("error, check ops\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    if (hvb_strnlen(rvt_ptn, HVB_MAX_PARTITION_NAME_LEN) >= HVB_MAX_PARTITION_NAME_LEN) {
        hvb_print("error, check rvt partition name\n");
        return HVB_ERROR_INVALID_ARGUMENT;
    }

    ptn_list = hash_ptn_list_add_rvt(hash_ptn_list, rvt_ptn);
    if (ptn_list == NULL) {
        hvb_print("error, add rvt\n");
        return HVB_ERROR_OOM;
    }

    vd = hvb_init_verified_data();
    if (!vd) {
        hvb_print("malloc verified_data fail\n");
        ret = HVB_ERROR_OOM;
        goto fail;
    }

    /* verity rvt cert */
    ret = hvb_rvt_verify_root(ops, rvt_ptn, ptn_list, vd);
    if (ret != HVB_OK) {
        hvb_print("error, verity rvt partition.\n");
        goto fail;
    }

    /* get rvt image */
    rvt_image = hvb_get_partition_image(vd, rvt_ptn);
    if (!rvt_image) {
        hvb_print("error, get rvt ptn.\n");
        ret = HVB_ERROR_OOM;
        goto fail;
    }

    /* walk verify all nodes from rvt */
    ret = hvb_walk_verify_nodes(ops, ptn_list, rvt_image, vd);
    if (ret != HVB_OK) {
        hvb_print("error, walk nodes.\n");
        goto fail;
    }

    hvb_print("hash algorithm is");
    hvb_print_u64(vd->algorithm);

    /* creat cmdline info */
    ret = hvb_creat_cmdline(ops, vd);
    if (ret != HVB_OK) {
        hvb_print("error, create cmdline.\n");
        goto fail;
    }

    *out_vd = vd;

fail:
    if (vd != NULL && ret != HVB_OK) {
        hvb_chain_verify_data_free(vd);
        hvb_free(vd);
    }

    hvb_free(ptn_list);

    return ret;
}

void hvb_chain_verify_data_free(struct hvb_verified_data *vd)
{
    uint64_t n;

    if (vd == NULL) {
        hvb_print("vd is NULL, do nothing\n");
        return;
    }

    for (n = 0; n < vd->num_loaded_certs && vd->certs; n++) {
        if (vd->certs[n].data.addr != NULL)
            hvb_free(vd->certs[n].data.addr);

        if (vd->certs[n].partition_name != NULL) {
            hvb_free(vd->certs[n].partition_name);
        }
    }

    if (vd->certs != NULL) {
        hvb_free(vd->certs);
    }

    for (n = 0; n < vd->num_loaded_images && vd->images; n++) {
        if (vd->images[n].data.addr != NULL)
            hvb_free(vd->images[n].data.addr);

        if (vd->images[n].partition_name != NULL)
            hvb_free(vd->images[n].partition_name);
    }

    if (vd->images != NULL) {
        hvb_free(vd->images);
    }

    if (vd->cmdline.buf != NULL) {
        hvb_free(vd->cmdline.buf);
    }

    hvb_memset((uint8_t *)vd, 0, sizeof(*vd));
}
