/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "linux/rpmb.h"

#include "ipc.h"
#include "log.h"
#include "rpmb.h"
#include "storage.h"

#define RPMB_BLOCK_SIZE sizeof(struct rpmb_frame)

static int rpmb_fd = -1;
static uint8_t read_buf[4096];

#ifdef RPMB_DEBUG

static void print_buf(const char *prefix, const uint8_t *buf, size_t size)
{
    size_t i;

    printf("%s @%p [%zu]", prefix, buf, size);
    for (i = 0; i < size; i++) {
        if (i && i % 32 == 0)
            printf("\n%*s", (int) strlen(prefix), "");
        printf(" %02x", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}

#endif /* RPMB_DEBUG */


int rpmb_dev_send(struct storage_msg *msg, const void *r, size_t req_len)
{
    int rc;
    uint32_t blocks;
    struct {
        struct rpmb_ioc_seq_cmd seq;
        struct rpmb_ioc_cmd cmd[3];
    } rpmb = {};
    struct rpmb_ioc_cmd *cmd = rpmb.seq.cmds;
    const struct storage_rpmb_send_req *req = r;

    if (req_len < sizeof(*req)) {
        ALOGW("malformed rpmb request: invalid length (%zu < %zu)\n",
              req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    size_t expected_len = sizeof(*req) + req->reliable_write_size + req->write_size;
    if (req_len != expected_len) {
        ALOGW("malformed rpmb request: invalid length (%zu != %zu)\n",
              req_len, expected_len);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    const uint8_t *write_buf = req->payload;
    if (req->reliable_write_size) {
        if ((req->reliable_write_size % RPMB_BLOCK_SIZE) != 0) {
            ALOGW("invalid reliable write size %u\n", req->reliable_write_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }


        blocks = req->reliable_write_size / RPMB_BLOCK_SIZE;
        rpmb_ioc_cmd_set(*cmd, RPMB_F_WRITE | RPMB_F_REL_WRITE, write_buf, blocks);

#ifdef RPMB_DEBUG
        ALOGI("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);
        //print_buf("request: ", write_buf, req->reliable_write_size);
#endif
        write_buf += req->reliable_write_size;
        rpmb.seq.num_of_cmds++;
        cmd++;
    }

    if (req->write_size) {
        if ((req->write_size % RPMB_BLOCK_SIZE) != 0) {
            ALOGW("invalid write size %u\n", req->write_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        blocks = req->write_size / RPMB_BLOCK_SIZE;
        rpmb_ioc_cmd_set(*cmd, RPMB_F_WRITE, write_buf, blocks);

#ifdef RPMB_DEBUG
        ALOGI("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);
        print_buf("request: ", write_buf, req->write_size);
#endif
        write_buf += req->write_size;
        rpmb.seq.num_of_cmds++;
        cmd++;
    }

    if (req->read_size) {
        if (req->read_size % RPMB_BLOCK_SIZE != 0 ||
            req->read_size > sizeof(read_buf)) {
            ALOGE("%s: invalid read size %u\n", __func__, req->read_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        blocks = req->read_size / RPMB_BLOCK_SIZE;
        rpmb_ioc_cmd_set(*cmd, 0, read_buf, blocks);

        rpmb.seq.num_of_cmds++;
        cmd++;
    }

    rc = ioctl(rpmb_fd, RPMB_IOC_SEQ_CMD, &rpmb.seq);
    if (rc < 0) {
        ALOGE("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        msg->result = STORAGE_ERR_GENERIC;
        goto err_response;
    }
#ifdef RPMB_DEBUG
    if (req->read_size)
        print_buf("response: ", read_buf, req->read_size);
#endif

    if (msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) {
        /*
         * Nothing todo for post msg commit request as RPMB_IOC_SEQ_CMD
         * is fully synchronous in this implementation.
         */
    }

    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, read_buf, req->read_size);

err_response:
    return ipc_respond(msg, NULL, 0);
}


int rpmb_dev_open(const char *rpmb_devname)
{
    int rc;

    rc = open(rpmb_devname, O_RDWR, 0);
    if (rc < 0) {
        ALOGE("unable (%d) to open rpmb device '%s': %s\n",
              errno, rpmb_devname, strerror(errno));
        return rc;
    }
    rpmb_fd = rc;
    return 0;
}

void rpmb_dev_close(void)
{
    close(rpmb_fd);
    rpmb_fd = -1;
}

