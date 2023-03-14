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
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/fs.h>

#include <errno.h>
#include <fcntl.h>

#include "hvb_ops.h"
#include "hvb.h"

static struct struct hvb_ops *g_hvb_ops;

static enum hvb_io_errno hvb_read_partition(struct hvb_ops *ops,
                                            const char *partition,
                                            int64_t offset,
                                            uint64_t num_bytes,
                                            void *buffer,
                                            uint64_t *out_num_read)
{
    int fd;
    off_t where;
    suint64_t num_read;
    enum hvb_io_errno ret = HVB_IO_OK;

    fd = open(partition, O_RDONLY);
    if (fd == -1) {
        printf("Error open %s partition.\n", partition);
        ret = HVB_IO_ERROR_NO_SUCH_PARTITION;
        goto out;
    }

    if (offset < 0) {
        uint64_t partition_size;
        if (ioctl(fd, BLKGETSIZE64, &partition_size) != 0) {
            printf("Error getting size of %s partition.\n", partition);
            ret = HVB_IO_ERROR_IO;
            goto out;
        }
        offset = partition_size - (-offset);
    }

    where = lseek(fd, offset, SEEK_SET);
    if (where == -1) {
        printf("Error seeking to offset.\n");
        ret = HVB_IO_ERROR_IO;
        goto out;
    } else if (where != offset) {
        printf("Error seeking to offset.\n");
        ret = HVB_IO_ERROR_RANGE_OUTSIDE_PARTITION;
        goto out;
    }

    num_read = read(fd, buffer, num_bytes);
    if (num_read == -1) {
        printf("Error reading data.\n");
        ret = HVB_IO_ERROR_IO;
        goto out;
    }

    if (out_num_read != NULL) {
        *out_num_read = num_read;
    }

out:
    if (fd != -1) {
        if (close(fd) != 0) {
            printf("Error closing file descriptor.\n");
        }
    }

    return ret;
}

static enum hvb_io_errno hvb_write_partition(struct hvb_ops *ops,
                                             const char *partition,
                                             int64_t offset,
                                             uint64_t num_bytes,
                                             const void *buffer)
{
    int fd;
    off_t where;
    suint64_t num_written;
    enum hvb_io_errno ret = HVB_IO_OK;

    fd = open(partition, O_WRONLY);
    if (fd == -1) {
        printf("Error opening %s partition.\n", partition);
        ret = HVB_IO_ERROR_IO;
        goto out;
    }

    where = lseek(fd, offset, SEEK_SET);
    if (where == -1) {
        printf("Error seeking to offset.\n");
        ret = HVB_IO_ERROR_IO;
        goto out;
    } else if (where != offset) {
        printf("Error seeking to offset.\n");
        ret = HVB_IO_ERROR_RANGE_OUTSIDE_PARTITION;
        goto out;
    }

    /* On Linux, we never get partial writes on block devices. */
    num_written = write(fd, buffer, num_bytes);
    if (num_written == -1) {
        printf("Error writing data.\n");
        ret = HVB_IO_ERROR_IO;
        goto out;
    }

out:
    if (fd != -1) {
        if (close(fd) != 0) {
            printf("Error closing file descriptor.\n");
        }
    }

    return ret;
}

static enum hvb_io_errno hvb_read_rollback(struct hvb_ops *ops,
                                           uint64_t rollback_index_location,
                                           uint64_t *out_rollback_index)
{
    if (out_rollback_index != NULL) {
        *out_rollback_index = 0;
    }

    return HVB_IO_OK;
}

static enum hvb_io_errno hvb_write_rollback(struct hvb_ops *ops,
                                            uint64_t rollback_index_location,
                                            uint64_t rollback_index)
{
    return HVB_IO_OK;
}

static enum hvb_io_errno hvb_get_partiton_uuid(struct hvb_ops *ops,
                                               const char *partition,
                                               char *uuid_buf,
                                               uint64_t uuid_buf_size)
{
    if (uuid_buf != NULL && uuid_buf_size > 0) {
        uuid_buf[0] = '\0';
    }

    return HVB_IO_OK;
}

static enum hvb_io_errno hvb_get_partiton_size(struct hvb_ops *ops,
                                               const char *partition,
                                               uint64_t *out_size_in_bytes)
{
    int fd;
    enum hvb_io_errno ret = HVB_IO_OK;

    fd = open(partition, O_WRONLY);
    if (fd == -1) {
        printf("Error opening %s partition.\n", partition);
        ret = HVB_IO_ERROR_IO;
        goto out;
    }

    if (out_size_in_bytes != NULL) {
        if (ioctl(fd, BLKGETSIZE64, out_size_in_bytes) != 0) {
            printf("Error getting size of %s partition.\n", partition);
            ret = HVB_IO_ERROR_IO;
            goto out;
        }
    }

out:
    if (fd != -1) {
        if (close(fd) != 0) {
            printf("Error closing file descriptor.\n");
        }
    }

    return ret;
}

static struct hvb_ops *hvb_ops_user(void)
{
    struct hvb_ops *hvb_ops;

    hvb_ops = (struct hvb_ops *)hvb_malloc(sizeof(struct hvb_ops));
    if (!hvb_ops) {
        printf("Error malloc for hvb_ops.\n");
        return NULL;
    }

    hvb_ops->user_data = hvb_ops;
    hvb_ops->read_partition = hvb_read_partition;
    hvb_ops->write_partition = hvb_write_partition;
    hvb_ops->read_rollback = hvb_read_rollback;
    hvb_ops->write_rollback = hvb_write_rollback;
    hvb_ops->get_partiton_uuid = hvb_get_partiton_uuid;
    hvb_ops->get_partiton_size = hvb_get_partiton_size;

    return hvb_ops;
}

int main(void)
{
    int ret = -1;
    enum hvb_errno sub_ret = HVB_OK;
    struct hvb_verified_data *verified_data = NULL;

    printf("hvb main function start.\n");
    g_hvb_ops = hvb_ops_user();
    if (!g_hvb_ops) {
        printf("failed to get hvb_ops_user.\n");
        goto out;
    }

    sub_ret = hvb_chain_verify(g_hvb_ops, "rvt", &verified_data);
    if (sub_ret != HVB_OK) {
        printf("hvb verity error.\n");
        goto out;
    }
    printf("hvb main end.\n");

out:
    if (g_hvb_ops != NULL) {
        hvb_free(g_hvb_ops);
    }

    return ret;
}
