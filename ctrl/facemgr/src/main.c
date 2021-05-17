/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file main.c
 * \brief Face manager daemon entry point
 */

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // sleep

#include <hicn/facemgr.h>
#include <hicn/facemgr/cfg.h>
#include <hicn/facemgr/loop.h>
#include <hicn/policy.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>

#include "cfg_file.h"

#define FACEMGR_TIMEOUT 3

#if 0
static struct event_base * loop;
#endif
static loop_t * loop = NULL;

#ifdef __linux__
#ifdef WITH_THREAD
static bool stop = false;
#endif /* WITH_THREAD */
#endif /* __linux__ */

static struct option long_options[] =
{
    {"config",  required_argument, 0, 'c'},
    {0, 0, 0, 0}
};

typedef struct {
    char * cfgfile;
} facemgr_options_t;

void usage(const char * progname)
{
    printf("%s: Face manager daemon\n", progname);
    printf("\n");
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -c  --config [FILE|none]    Sets the configuration file (unless none, default: /etc/facemgr.conf, ~/facemgr.conf)\n");
    printf("\n");
}

void facemgr_signal_handler(int signal) {
    fprintf(stderr, "Received ^C... quitting !\n");
    if (loop) {
        loop_break(loop);
#ifdef __linux__
#ifdef WITH_THREAD
    stop = true;
#endif /* WITH_THREAD */
#endif /* __linux__ */
    }
}

int parse_cmdline(int argc, char ** argv, facemgr_options_t * opts)
{
    int c;
    while ((c = getopt_long(argc, argv, "c:", long_options, NULL)) != -1) {
        switch(c) {
            case 'c':
                opts->cfgfile = optarg;
                break;
            case ':':
            case '?':
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }

    }
    return 0;
}

#ifdef __linux__

#endif /* __linux__ */

int
dump_facelet(const facemgr_t * facemgr, const facelet_t * facelet,
        void * user_data)
{
    char facelet_s[MAXSZ_FACELET];
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet);
    DEBUG("%s", facelet_s);
    return 0;
}

int main(int argc, char ** argv)
{
    facemgr_cfg_t * cfg = NULL;
    facemgr_t * facemgr;

    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = facemgr_signal_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    char cfgfile[PATH_MAX];

    // TODO: default < config < commandline on a per option basis

    /* Commandline */
    facemgr_options_t cmdline_opts = {0};
    if (parse_cmdline(argc, argv, &cmdline_opts) < 0) {
        ERROR("Error parsing commandline");
        goto ERR_CMDLINE;
    }

    /* Configuration file */
    //facemgr_options_t cfgfile_opts;

    if (cmdline_opts.cfgfile) {
        if (strcasecmp(cmdline_opts.cfgfile, "none") == 0)
            goto NO_CFGFILE;

        if (!realpath(cmdline_opts.cfgfile, (char*)&cfgfile))
            goto ERR_PATH;

        goto PARSE_CFGFILE;
    }

    /* No commandline path specifed, probe default locations... */

    if (probe_cfgfile(cfgfile) < 0)
        goto NO_CFGFILE;

PARSE_CFGFILE:

    DEBUG("Using configuration file %s", cfgfile);
    cfg = facemgr_cfg_create();
    if (!cfg)
        goto ERR_FACEMGR_CFG;

    if (parse_config_file(cfgfile, cfg) < 0) {
        ERROR("Error parsing configuration file %s", cfgfile);
        goto ERR_PARSE;
    }

    facemgr = facemgr_create_with_config(cfg);
    if (!facemgr)
        goto ERR_FACEMGR_CONFIG;

    goto MAIN_LOOP;

NO_CFGFILE:

    facemgr = facemgr_create();
    if (!facemgr)
        goto ERR_FACEMGR;

MAIN_LOOP:

    /* Main loop */
    loop = loop_create();
    facemgr_set_callback(facemgr, loop, (void*)loop_callback);

#ifdef __ANDROID__
    facemgr_set_jvm(facemgr, NULL);
#endif /* __ ANDROID__ */

    DEBUG("Bootstrap...");

    if (facemgr_bootstrap(facemgr) < 0 )
        goto ERR_BOOTSTRAP;

    if (loop_dispatch(loop) < 0) {
        ERROR("Failed to run main loop");
        return EXIT_FAILURE;
    }

#ifdef __linux__
#ifdef WITH_THREAD
    unsigned cpt = 0;
    while(!stop) {
        if (cpt == 10) {
            DEBUG("<facelets>");
#if 1
            facemgr_list_facelets(facemgr, dump_facelet, NULL);
#else
            char * buffer;
            int n = facemgr_list_facelets_json(facemgr, &buffer);
            printf("%s\n", buffer);
            free(buffer);
#endif

            DEBUG("</facelets>");
            cpt = 0;
        }
        usleep(500000);
        cpt++;
    }
#endif /* WITH_THREAD */
#endif /* __linux__ */

    facemgr_stop(facemgr);

    if (loop_undispatch(loop) < 0) {
        ERROR("Failed to terminate main loop");
        return EXIT_FAILURE;
    }

    facemgr_free(facemgr);

    if (cfg)
        facemgr_cfg_free(cfg);

    loop_free(loop);

    return EXIT_SUCCESS;

ERR_BOOTSTRAP:

    facemgr_free(facemgr);
    loop_free(loop);
ERR_FACEMGR_CONFIG:
ERR_FACEMGR:
ERR_PARSE:
    if (cfg)
        facemgr_cfg_free(cfg);
ERR_FACEMGR_CFG:

ERR_PATH:
ERR_CMDLINE:
    return EXIT_FAILURE;


}
