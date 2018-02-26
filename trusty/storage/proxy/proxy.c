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
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/sysmacros.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/major.h>

#include <cutils/android_filesystem_config.h>

#include "ipc.h"
#include "log.h"
#include "rpmb.h"
#include "rpmb-dev.h"
#include "rpmb-sim.h"
#include "storage.h"

#define REQ_BUFFER_SIZE 4096
/* /dev/block/mmcblk1p13 */
#define RPMB_SIM_DEV_NAME       "/dev/block/by-name/teedata"

static uint8_t req_buffer[REQ_BUFFER_SIZE + 1];

static unsigned int rpmb_sim;

static const char *ss_data_root;
static const char *trusty_devname;
static const char *rpmb_devname;
static const char *ss_srv_name = STORAGE_DISK_PROXY_PORT;

static const char *_sopts = "hp:d:r:";
static const struct option _lopts[] =  {
    {"help",       no_argument,       NULL, 'h'},
    {"trusty_dev", required_argument, NULL, 'd'},
    {"data_path",  required_argument, NULL, 'p'},
    {"rpmb_dev",   required_argument, NULL, 'r'},
    {0, 0, 0, 0}
};

static void show_usage_and_exit(int code)
{
    ALOGE("usage: storageproxyd -d <trusty_dev> -p <data_path> -r <rpmb_dev>\n");
    exit(code);
}

static int handle_req(struct storage_msg *msg, const void *req, size_t req_len)
{
    int rc;

    if ((msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) &&
        (msg->cmd != STORAGE_RPMB_SEND)) {
        /*
         * handling post commit messages on non rpmb commands are not
         * implemented as there is no use case for this yet.
         */
        ALOGE("cmd 0x%x: post commit option is not implemented\n", msg->cmd);
        msg->result = STORAGE_ERR_UNIMPLEMENTED;
        return ipc_respond(msg, NULL, 0);
    }

    if (msg->flags & STORAGE_MSG_FLAG_PRE_COMMIT) {
        rc = storage_sync_checkpoint();
        if (rc < 0) {
            msg->result = STORAGE_ERR_GENERIC;
            return ipc_respond(msg, NULL, 0);
        }
    }

    switch (msg->cmd) {
    case STORAGE_FILE_DELETE:
        rc = storage_file_delete(msg, req, req_len);
        break;

    case STORAGE_FILE_OPEN:
        rc = storage_file_open(msg, req, req_len);
        break;

    case STORAGE_FILE_CLOSE:
        rc = storage_file_close(msg, req, req_len);
        break;

    case STORAGE_FILE_WRITE:
        rc = storage_file_write(msg, req, req_len);
        break;

    case STORAGE_FILE_READ:
        rc = storage_file_read(msg, req, req_len);
        break;

    case STORAGE_FILE_GET_SIZE:
        rc = storage_file_get_size(msg, req, req_len);
        break;

    case STORAGE_FILE_SET_SIZE:
        rc = storage_file_set_size(msg, req, req_len);
        break;

    case STORAGE_RPMB_SEND:
        if (rpmb_sim)
            rc = rpmb_sim_send(msg, req, req_len);
        else
            rc = rpmb_dev_send(msg, req, req_len);
        break;

    default:
        ALOGE("unhandled command 0x%x\n", msg->cmd);
        msg->result = STORAGE_ERR_UNIMPLEMENTED;
        rc = 1;
    }

    if (rc > 0) {
        /* still need to send response */
        rc = ipc_respond(msg, NULL, 0);
    }
    return rc;
}

static int proxy_loop(void)
{
    ssize_t rc;
    struct storage_msg msg;

    /* enter main message handling loop */
    while (true) {

        /* get incoming message */
        rc = ipc_get_msg(&msg, req_buffer, REQ_BUFFER_SIZE);
        if (rc < 0)
            return rc;

        /* handle request */
        req_buffer[rc] = 0; /* force zero termination */
        rc = handle_req(&msg, req_buffer, rc);
        if (rc)
            return rc;
    }

    return 0;
}

static void parse_args(int argc, char *argv[])
{
    int opt;
    int oidx = 0;

    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1) {
        switch (opt) {

        case 'd':
            trusty_devname = strdup(optarg);
            break;

        case 'p':
            ss_data_root = strdup(optarg);
            break;

        case 'r':
            rpmb_devname = strdup(optarg);
            break;

        default:
            ALOGE("unrecognized option (%c):\n", opt);
            show_usage_and_exit(EXIT_FAILURE);
        }
    }

    if (ss_data_root == NULL ||
        trusty_devname == NULL ||
        rpmb_devname == NULL) {
        ALOGE("missing required argument(s)\n");
        show_usage_and_exit(EXIT_FAILURE);
    }

    ALOGI("starting storageproxyd\n");
    ALOGI("storage data root: %s\n", ss_data_root);
    ALOGI("trusty dev: %s\n", trusty_devname);
    ALOGI("rpmb dev: %s\n", rpmb_devname);
}

int main(int argc, char *argv[])
{
    int rc;

    rc = rpmb_sim_open(RPMB_SIM_DEV_NAME);
    if (rc < 0)
        rpmb_sim = 0;
    else
        rpmb_sim = is_use_sim_rpmb();

    if (rpmb_sim)
        ALOGI("storage use simulation rpmb.\n");
    else
        ALOGI("storage use physical rpmb.\n");

    /* parse arguments */
    parse_args(argc, argv);

    /* initialize secure storage directory */
    rc = storage_init(ss_data_root);
    if (rc < 0)
        return EXIT_FAILURE;

    if (!rpmb_sim) {
        rpmb_sim_close();
        rc = rpmb_dev_open(rpmb_devname);
    }

    if (rc < 0)
        return EXIT_FAILURE;

    /* connect to Trusty secure storage server */
    rc = ipc_connect(trusty_devname, ss_srv_name);
    if (rc < 0)
        return EXIT_FAILURE;

    /* enter main loop */
    rc = proxy_loop();
    ALOGE("exiting proxy loop with status (%d)\n", rc);

    ipc_disconnect();

    if (rpmb_sim)
        rpmb_sim_close();
    else
        rpmb_dev_close();

    return (rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
