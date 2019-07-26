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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // faccess

#include <libconfig.h>

#include "util/log.h"
#include "util/policy.h"

#ifdef __APPLE__
#include <Dispatch/Dispatch.h>
#else
// Note: we might want to use libevent on Apple too
#include <event2/event.h>
#endif

#include "facemgr.h"

#define FACEMGR_TIMEOUT 3


static struct option long_options[] =
{
    {"config",  required_argument, 0, 'c'},
    {0, 0, 0, 0}
};

typedef struct {
    char * cfgfile;
} facemgr_options_t;

static const char * DEFAULT_CFGFILES[] = {
    "/etc/facemgr.conf",
    "~/facemgr.conf",
};

#define ARRAYSIZE(x) (sizeof(x)/sizeof(*x))

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

int probe_cfgfile(char * f)
{
    for (unsigned i = 0; i < ARRAYSIZE(DEFAULT_CFGFILES); i++) {
        if (access(DEFAULT_CFGFILES[i], F_OK ) != -1) {
            if (!realpath(DEFAULT_CFGFILES[i], f))
                continue;
            return 0;
        }
    }
    return -1;
}

int parse_cmdline(int argc, char ** argv, facemgr_options_t * opts)
{
    int c;
    while ((c = getopt_long(argc, argv, "c:", long_options, NULL)) != -1) {
        switch(c) {
            case 'c':
                opts->cfgfile = strdup(optarg);
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

int parse_config_file(const char * cfgpath, facemgr_t * facemgr)
{
    /* Reading configuration file */
    config_t cfg;
    config_setting_t *setting;

    config_init(&cfg);

    /* Read the file. If there is an error, report it and exit. */
    if(!config_read_file(&cfg, cfgpath))
        goto ERR_FILE;

    setting = config_lookup(&cfg, "log");
    if (setting) {
        const char *log_level_str;
        if (config_setting_lookup_string(setting, "log_level", &log_level_str)) {
            if (strcmp(log_level_str, "FATAL") == 0) {
                log_conf.log_level = LOG_FATAL;
            } else
            if (strcmp(log_level_str, "ERROR") == 0) {
                log_conf.log_level = LOG_ERROR;
            } else
            if (strcmp(log_level_str, "WARN") == 0) {
                log_conf.log_level = LOG_WARN;
            } else
            if (strcmp(log_level_str, "INFO") == 0) {
                log_conf.log_level = LOG_INFO;
            } else
            if (strcmp(log_level_str, "DEBUG") == 0) {
                log_conf.log_level = LOG_DEBUG;
            } else
            if (strcmp(log_level_str, "TRACE") == 0) {
                log_conf.log_level = LOG_TRACE;
            } else {
                printf("Ignored unknown log level\n");
            }
        }
    }

    setting = config_lookup(&cfg, "faces.overlay.ipv4");
    if (setting) {
        const char * ip_address;
        int local_port, remote_port;
        if (config_setting_lookup_int(setting, "local_port", &local_port)) {
            if ((local_port < 0) || (local_port > MAX_PORT))
                goto ERR;
            facemgr->overlay_v4_local_port = (uint16_t)local_port;
        }

        if (config_setting_lookup_int(setting, "remote_port", &remote_port)) {
            if ((remote_port < 0) || (remote_port > MAX_PORT))
                goto ERR;
            facemgr->overlay_v4_remote_port = (uint16_t)remote_port;
        }

        if (config_setting_lookup_string(setting, "remote_addr", &ip_address)) {
            ip_address_pton(ip_address, &facemgr->overlay_v4_remote_addr);
            printf("got v4 remote addr\n");
        }
    }

    setting = config_lookup(&cfg, "faces.overlay.ipv6");
    if (setting) {
        const char * ip_address;
        int local_port, remote_port;
        if (config_setting_lookup_int(setting, "local_port", &local_port)) {
            if ((local_port < 0) || (local_port > MAX_PORT))
                goto ERR;
            facemgr->overlay_v6_local_port = (uint16_t)local_port;
        }

        if (config_setting_lookup_int(setting, "remote_port", &remote_port)) {
            if ((remote_port < 0) || (remote_port > MAX_PORT))
                goto ERR;
            facemgr->overlay_v6_remote_port = (uint16_t)remote_port;
        }

        if (config_setting_lookup_string(setting, "remote_addr", &ip_address))
            ip_address_pton(ip_address, &facemgr->overlay_v6_remote_addr);
    }

    setting = config_lookup(&cfg, "faces.rules");
    if (setting) {
        int count = config_setting_length(setting);
        for(unsigned i = 0; i < count; ++i) {
            const char *interface_name;
            policy_tags_t tags = POLICY_TAGS_EMPTY;

            config_setting_t *rule = config_setting_get_elem(setting, i);

            /* Interface name */
            if(!(config_setting_lookup_string(rule, "name", &interface_name)))
                continue;

            /* Associated tags */
            config_setting_t *tag_settings = config_setting_get_member(rule, "tags");
            if (!tag_settings)
                goto ERR;


            for (unsigned j = 0; j < config_setting_length(tag_settings); j++) {
                const char * tag_str = config_setting_get_string_elem(tag_settings, j);
                policy_tag_t tag = policy_tag_from_str(tag_str);
                if (tag == POLICY_TAG_N)
                    goto ERR;
                policy_tags_add(&tags, tag);
            }

            /* debug */
            char tags_str[MAXSZ_POLICY_TAGS];
            policy_tags_snprintf(tags_str, MAXSZ_POLICY_TAGS, tags);
            printf("Rule #%d interface_name=%s, tags=%s\n", i, interface_name, tags_str);
            face_rules_add(&facemgr->rules, strdup(interface_name), tags);
        }
    }

    config_destroy(&cfg);
    return 0;

ERR_FILE:
    printf("Could not read configuration file %s\n", cfgpath);
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    exit(EXIT_FAILURE);
    return -1;
ERR:
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return -1;
}

#ifndef APPLE
void dummy_handler(int fd, short event, void *arg) { }
#endif /* APPLE */


int main(int argc, char **argv)
{
    facemgr_t * facemgr = facemgr_create();
    if (!facemgr)
        goto ERR_FACEMGR;

    char cfgfile[PATH_MAX];

    // TODO: default < config < commandline on a per option basis

    /* Commandline */
    facemgr_options_t cmdline_opts = {0};
    if (parse_cmdline(argc, argv, &cmdline_opts) < 0) {
        ERROR("Error parsing commandline\n");
        goto ERR_CMDLINE;
    }

    /* Configuration file */
    //facemgr_options_t cfgfile_opts;

    if (cmdline_opts.cfgfile) {
        if (strcmp(cmdline_opts.cfgfile, "none") == 0)
            goto NO_CFGFILE;

        if (!realpath(cmdline_opts.cfgfile, (char*)&cfgfile))
            goto ERR_PATH;

        goto PARSE_CFGFILE;
    }

    /* No commandline path specifed, probe default locations... */

    if (probe_cfgfile(cfgfile) < 0)
        goto NO_CFGFILE;

    printf("Using configuration file %s\n", cfgfile);

PARSE_CFGFILE:

    if (parse_config_file(cfgfile, facemgr) < 0) {
        ERROR("Error parsing configuration file %s\n", cfgfile);
        goto ERR_PARSE;
    }

NO_CFGFILE:

#ifdef __linux__
    facemgr->loop = event_base_new();
    if (!facemgr->loop)
        fatal("Could not create an event base");

    /* Main loop
     *
     * To avoid the loop to exit when empty, we might either rely on an option
     * introduced from versions 2.1.x:
     *   event_base_loop(loop->base, EVLOOP_NO_EXIT_ON_EMPTY);
     * or use this workaround:
     *   http://archives.seul.org/libevent/users/Sep-2012/msg00056.html
     *
     * TODO:
     *  - HUP should interrupt the main loop
     */
    {
        struct event *ev;
        struct timeval tv;
        tv.tv_sec = FACEMGR_TIMEOUT;
        tv.tv_usec = 0;

        ev = event_new(facemgr->loop, fileno(stdin), EV_TIMEOUT | EV_PERSIST, dummy_handler, NULL);
        event_add(ev, &tv);
    }
#endif /* __linux__ */

    DEBUG("Bootstrap...\n");
    if (facemgr_bootstrap(facemgr) < 0 )
        goto ERR_BOOTSTRAP;

#ifdef __linux__
    event_set_log_callback(NULL);
    event_base_dispatch(facemgr->loop);

    event_base_free(facemgr->loop);
#endif /* __linux__ */

#ifdef __APPLE__
    /* Main loop */
    facemgr->loop = NULL;
    dispatch_main();
#endif /* __APPLE__ */

    /* Clean up */
    //interface_delete_all();


    facemgr_free(facemgr);

    return EXIT_SUCCESS;

ERR_BOOTSTRAP:
ERR_PARSE:
ERR_PATH:
ERR_CMDLINE:
    facemgr_free(facemgr);
ERR_FACEMGR:
    return EXIT_FAILURE;

}

