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

#ifdef WITH_THREAD
#ifndef __linux__
#error "Not implemented"
#endif /* __linux__ */
#include <pthread.h>
#endif /* WITH_THREAD */

#ifndef __APPLE__
#include <event2/event.h>
#include <event2/thread.h>
#endif /* __APPLE__ */

#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // faccess

#include <libconfig.h>

#ifdef __APPLE__
#include <Dispatch/Dispatch.h>
#else
#include <event2/event.h>
#endif

#include <hicn/facemgr.h>
#include <hicn/policy.h>

#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>

#include <hicn/facemgr/cfg.h>

#define FACEMGR_TIMEOUT 3

static struct event_base * loop;

void facemgr_signal_handler(int signal) {
    fprintf(stderr, "Received ^C... quitting !\n");
    exit(0);
#if 0
    return;

    // FIXME

    /* should be atomic */
    // FIXME Don't use loop in a static variable as we should not need it if all
    // events are properly unregistered...
#endif
#ifdef __linux__
    event_base_loopbreak(loop);
#endif /* __linux__ */
    loop = NULL;
}

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

int
parse_config_global(facemgr_cfg_t * cfg, config_setting_t * setting)
{
    /* - face_type */

    const char *face_type_str;
    facemgr_face_type_t face_type;
    if (config_setting_lookup_string(setting, "face_type", &face_type_str)) {
        if (strcasecmp(face_type_str, "auto") == 0) {
            face_type = FACEMGR_FACE_TYPE_DEFAULT;
        } else
        if (strcasecmp(face_type_str, "native-udp") == 0) {
            face_type = FACEMGR_FACE_TYPE_NATIVE_UDP;
        } else
        if (strcasecmp(face_type_str, "native-tcp") == 0) {
            face_type = FACEMGR_FACE_TYPE_NATIVE_TCP;
        } else
        if (strcasecmp(face_type_str, "overlay-udp") == 0) {
            face_type = FACEMGR_FACE_TYPE_OVERLAY_UDP;
        } else
        if (strcasecmp(face_type_str, "overlay-tcp") == 0) {
            face_type = FACEMGR_FACE_TYPE_OVERLAY_TCP;
        } else {
            ERROR("Invalid face type in section 'global'");
            return -1;
        }

        int rc = facemgr_cfg_set_face_type(cfg, &face_type);
        if (rc < 0)
            goto ERR;
    }

    /* - disable_discovery */

    int disable_discovery;
    if (config_setting_lookup_bool(setting, "disable_discovery",
                &disable_discovery)) {
        int rc = facemgr_cfg_set_discovery(cfg, !disable_discovery);
        if (rc < 0)
            goto ERR;
    }

    /* - disable_ipv4 */

    int disable_ipv4;
    if (config_setting_lookup_bool(setting, "disable_ipv4",
                &disable_ipv4)) {
        INFO("Ignored setting 'disable_ipv4' in section 'global' (not implemented).");
#if 0
        int rc = facemgr_cfg_set_ipv4(cfg, !disable_ipv4);
        if (rc < 0)
            goto ERR;
#endif
    }

    /* - disable ipv6 */

    int disable_ipv6;
    if (config_setting_lookup_bool(setting, "disable_ipv6",
                &disable_ipv6)) {
        INFO("Ignored setting 'disable_ipv6' in section 'global': (not implemented).");
#if 0
        int rc = facemgr_cfg_set_ipv6(cfg, !disable_ipv6);
        if (rc < 0)
            goto ERR;
#endif
    }

    /* - overlay */
    config_setting_t *overlay = config_setting_get_member(setting, "overlay");
    if (overlay) {

        /* ipv4 */
        config_setting_t *overlay_v4 = config_setting_get_member(overlay, "ipv4");
        if (overlay_v4) {
            const char * local_addr_str, * remote_addr_str;
            ip_address_t local_addr, remote_addr;
            ip_address_t * local_addr_p = NULL;
            ip_address_t * remote_addr_p = NULL;
            int local_port = 0;
            int remote_port = 0;

            if (config_setting_lookup_string(overlay_v4, "local_addr", &local_addr_str)) {
                ip_address_pton(local_addr_str, &local_addr);
                local_addr_p = &local_addr;
            }

            if (config_setting_lookup_int(overlay_v4, "local_port", &local_port)) {
                if (!IS_VALID_PORT(local_port))
                    goto ERR;
            }

            if (config_setting_lookup_string(overlay_v4, "remote_addr", &remote_addr_str)) {
                ip_address_pton(remote_addr_str, &remote_addr);
                remote_addr_p = &remote_addr;
            }

            if (config_setting_lookup_int(overlay_v4, "remote_port", &remote_port)) {
                if (!IS_VALID_PORT(remote_port))
                    goto ERR;
            }
            int rc = facemgr_cfg_set_overlay(cfg, AF_INET,
                    local_addr_p, local_port,
                    remote_addr_p, remote_port);
            if (rc < 0)
                goto ERR;
        }

        /* ipv6 */
        config_setting_t *overlay_v6 = config_setting_get_member(overlay, "ipv6");
        if (overlay_v6) {
            const char * local_addr_str, * remote_addr_str;
            ip_address_t local_addr, remote_addr;
            ip_address_t * local_addr_p = NULL;
            ip_address_t * remote_addr_p = NULL;
            int local_port = 0;
            int remote_port = 0;

            if (config_setting_lookup_string(overlay_v6, "local_addr", &local_addr_str)) {
                ip_address_pton(local_addr_str, &local_addr);
                local_addr_p = &local_addr;
            }

            if (config_setting_lookup_int(overlay_v6, "local_port", &local_port)) {
                if (!IS_VALID_PORT(local_port))
                    goto ERR;
            }

            if (config_setting_lookup_string(overlay_v6, "remote_addr", &remote_addr_str)) {
                ip_address_pton(remote_addr_str, &remote_addr);
                remote_addr_p = &remote_addr;
            }

            if (config_setting_lookup_int(overlay_v6, "remote_port", &remote_port)) {
                if (!IS_VALID_PORT(remote_port))
                    goto ERR;
            }
            int rc = facemgr_cfg_set_overlay(cfg, AF_INET6,
                    local_addr_p, local_port,
                    remote_addr_p, remote_port);
            if (rc < 0)
                goto ERR;
        }

    } /* overlay */

    return 0;

ERR:
    return -1;
}

int
parse_config_rules(facemgr_cfg_t * cfg, config_setting_t * setting)
{
    /* List of match-override tuples */
    facemgr_cfg_rule_t * rule;

    int count = config_setting_length(setting);
    for (unsigned i = 0; i < count; ++i) {
        config_setting_t * rule_setting = config_setting_get_elem(setting, i);

        /* Sanity check */

        config_setting_t * match_setting = config_setting_get_member(rule_setting, "match");
        if (!match_setting) {
            ERROR("Missing match section in rule #%d", i);
            goto ERR_CHECK;
        }

        config_setting_t * override_setting = config_setting_get_member(rule_setting, "override");
        if (!override_setting) {
            ERROR("Missing override section in rule #%d", i);
            goto ERR_CHECK;
        }

        rule = facemgr_cfg_rule_create();
        if (!rule)
            goto ERR_RULE;

        /* Parse match */

        const char * interface_name = NULL;
        config_setting_lookup_string(match_setting, "interface_name", &interface_name);

        const char * interface_type_str;
        netdevice_type_t interface_type = NETDEVICE_TYPE_UNDEFINED;
        if (config_setting_lookup_string(match_setting, "interface_type", &interface_type_str)) {
            if (strcasecmp(interface_type_str, "wired") == 0) {
                interface_type = NETDEVICE_TYPE_WIRED;
            } else
            if (strcasecmp(interface_type_str, "wifi") == 0) {
                interface_type = NETDEVICE_TYPE_WIFI;
            } else
            if (strcasecmp(interface_type_str, "cellular") == 0) {
                interface_type = NETDEVICE_TYPE_CELLULAR;
            } else {
                ERROR("Unknown interface type in rule #%d", i);
                goto ERR;
            }
        }

        if ((!interface_name) && (interface_type == NETDEVICE_TYPE_UNDEFINED)) {
            ERROR("Empty match section in rule #%d", i);
            goto ERR;
        }

        /* Associate match to rule */

        int rc = facemgr_cfg_rule_set_match(rule, interface_name, interface_type);
        if (rc < 0)
            goto ERR;

        /* Parse override */

        /* - face_type */

        const char *face_type_str;
        facemgr_face_type_t face_type;
        if (config_setting_lookup_string(override_setting, "face_type", &face_type_str)) {
            if (strcasecmp(face_type_str, "auto")) {
                /* We currently hardcode different behaviours based on the OS */
#ifdef __ANDROID__
                face_type = FACEMGR_FACE_TYPE_OVERLAY_UDP;
#else
                face_type = FACEMGR_FACE_TYPE_NATIVE_TCP;
#endif
            } else
            if (strcasecmp(face_type_str, "native-udp") == 0) {
                face_type = FACEMGR_FACE_TYPE_NATIVE_UDP;
            } else
            if (strcasecmp(face_type_str, "native-tcp") == 0) {
                face_type = FACEMGR_FACE_TYPE_NATIVE_TCP;
            } else
            if (strcasecmp(face_type_str, "overlay-udp") == 0) {
                face_type = FACEMGR_FACE_TYPE_OVERLAY_UDP;
            } else
            if (strcasecmp(face_type_str, "overlay-tcp") == 0) {
                face_type = FACEMGR_FACE_TYPE_OVERLAY_TCP;
            } else {
                ERROR("Invalid face type in section 'global'");
                return -1;
            }

            int rc = facemgr_cfg_rule_set_face_type(rule, &face_type);
            if (rc < 0)
                goto ERR;
        }

        /* - disable_discovery */

        int disable_discovery;
        if (config_setting_lookup_bool(override_setting, "disable_discovery",
                    &disable_discovery)) {
            int rc = facemgr_cfg_rule_set_discovery(rule, !disable_discovery);
            if (rc < 0)
                goto ERR;
        }

        /* - disable_ipv4 */

        int disable_ipv4;
        if (config_setting_lookup_bool(override_setting, "disable_ipv4",
                    &disable_ipv4)) {
            INFO("Ignored setting 'disable_ipv4' in rule #%d (not implemented).", i);
#if 0
            int rc = facemgr_cfg_rule_set_ipv4(rule, !disable_ipv4);
            if (rc < 0)
                goto ERR;
#endif
        }

        /* - disable ipv6 */

        int disable_ipv6;
        if (config_setting_lookup_bool(override_setting, "disable_ipv6",
                    &disable_ipv6)) {
            INFO("Ignored setting 'disable_ipv6' in rule #%d (not implemented).", i);
#if 0
            int rc = facemgr_cfg_rule_set_ipv6(rule, !disable_ipv6);
            if (rc < 0)
                goto ERR;
#endif
        }

        /* - ignore */
        int ignore;
        if (config_setting_lookup_bool(override_setting, "ignore", &ignore)) {
            int rc = facemgr_cfg_rule_set_ignore(rule, !!ignore);
            if (rc < 0)
                goto ERR;
        }

        /* - tags */
        config_setting_t *tag_settings = config_setting_get_member(override_setting, "tags");
        if (tag_settings) {
            INFO("Ignored setting 'tags' in rule #%d (not implemented).", i);
#if 0
            policy_tags_t tags = POLICY_TAGS_EMPTY;
            for (unsigned j = 0; j < config_setting_length(tag_settings); j++) {
                const char * tag_str = config_setting_get_string_elem(tag_settings, j);
                policy_tag_t tag = policy_tag_from_str(tag_str);
                if (tag == POLICY_TAG_N)
                    goto ERR;
                policy_tags_add(&tags, tag);
            }

            int rc = facemgr_cfg_rule_set_tags(rule, tags);
            if (rc < 0)
                goto ERR;

#if 0
            char tags_str[MAXSZ_POLICY_TAGS];
            policy_tags_snprintf(tags_str, MAXSZ_POLICY_TAGS, tags);
            DEBUG("Added tags tags=%s", tags_str);
#endif
#endif
        }

        /* - overlay */
        config_setting_t *overlay = config_setting_get_member(override_setting, "overlay");
        if (overlay) {

            /* ipv4 */
            config_setting_t *overlay_v4 = config_setting_get_member(overlay, "ipv4");
            if (overlay_v4) {
                const char * local_addr_str, * remote_addr_str;
                ip_address_t local_addr, remote_addr;
                ip_address_t * local_addr_p = NULL;
                ip_address_t * remote_addr_p = NULL;
                int local_port = 0;
                int remote_port = 0;

                if (config_setting_lookup_string(overlay_v4, "local_addr", &local_addr_str)) {
                    ip_address_pton(local_addr_str, &local_addr);
                    local_addr_p = &local_addr;
                }

                if (config_setting_lookup_int(overlay_v4, "local_port", &local_port)) {
                    if (!IS_VALID_PORT(local_port))
                        goto ERR;
                }

                if (config_setting_lookup_string(overlay_v4, "remote_addr", &remote_addr_str)) {
                    ip_address_pton(remote_addr_str, &remote_addr);
                    remote_addr_p = &remote_addr;
                }

                if (config_setting_lookup_int(overlay_v4, "remote_port", &remote_port)) {
                    if (!IS_VALID_PORT(remote_port))
                        goto ERR;
                }
                int rc = facemgr_cfg_rule_set_overlay(rule, AF_INET,
                        local_addr_p, local_port,
                        remote_addr_p, remote_port);
                if (rc < 0)
                    goto ERR;
            }

            /* ipv6 */
            config_setting_t *overlay_v6 = config_setting_get_member(overlay, "ipv6");
            if (overlay_v6) {
                const char * local_addr_str, * remote_addr_str;
                ip_address_t local_addr, remote_addr;
                ip_address_t * local_addr_p = NULL;
                ip_address_t * remote_addr_p = NULL;
                int local_port = 0;
                int remote_port = 0;

                if (config_setting_lookup_string(overlay_v6, "local_addr", &local_addr_str)) {
                    ip_address_pton(local_addr_str, &local_addr);
                    local_addr_p = &local_addr;
                }

                if (config_setting_lookup_int(overlay_v6, "local_port", &local_port)) {
                    if (!IS_VALID_PORT(local_port))
                        goto ERR;
                }

                if (config_setting_lookup_string(overlay_v6, "remote_addr", &remote_addr_str)) {
                    ip_address_pton(remote_addr_str, &remote_addr);
                    remote_addr_p = &remote_addr;
                }

                if (config_setting_lookup_int(overlay_v6, "remote_port", &remote_port)) {
                    if (!IS_VALID_PORT(remote_port))
                        goto ERR;
                }
                int rc = facemgr_cfg_rule_set_overlay(rule, AF_INET6,
                        local_addr_p, local_port,
                        remote_addr_p, remote_port);
                if (rc < 0)
                    goto ERR;
            }

        } /* overlay */

        /* Add newly created rule */

        rc = facemgr_cfg_add_rule(cfg, rule);
        if (rc < 0)
            goto ERR;
    }
    return 0;

ERR:
    facemgr_cfg_rule_free(rule);
ERR_RULE:
ERR_CHECK:
    return -1;
}

/* Currently not using facemgr_cfg_t */
int
parse_config_log(facemgr_cfg_t * cfg, config_setting_t * setting)
{
    const char *log_level_str;
    if (config_setting_lookup_string(setting, "log_level", &log_level_str)) {
        if (strcasecmp(log_level_str, "FATAL") == 0) {
            log_conf.log_level = LOG_FATAL;
        } else
        if (strcasecmp(log_level_str, "ERROR") == 0) {
            log_conf.log_level = LOG_ERROR;
        } else
        if (strcasecmp(log_level_str, "WARN") == 0) {
            log_conf.log_level = LOG_WARN;
        } else
        if (strcasecmp(log_level_str, "INFO") == 0) {
            log_conf.log_level = LOG_INFO;
        } else
        if (strcasecmp(log_level_str, "DEBUG") == 0) {
            log_conf.log_level = LOG_DEBUG;
        } else
        if (strcasecmp(log_level_str, "TRACE") == 0) {
            log_conf.log_level = LOG_TRACE;
        } else {
            ERROR("Invalid log level in section 'log'");
            return -1;
        }
    }
    return 0;
}

int
parse_config_file(const char * cfgpath, facemgr_cfg_t * cfg)
{
    /* Reading configuration file */
    config_t cfgfile;
    config_setting_t *setting;

    config_init(&cfgfile);

    /* Read the file. If there is an error, report it and exit. */
    if(!config_read_file(&cfgfile, cfgpath))
        goto ERR_FILE;

    setting = config_lookup(&cfgfile, "global");
    if (setting) {
        int rc = parse_config_global(cfg, setting);
        if (rc < 0)
            goto ERR_PARSE;
    }

    setting = config_lookup(&cfgfile, "rules");
    if (setting) {
        int rc = parse_config_rules(cfg, setting);
        if (rc < 0)
            goto ERR_PARSE;
    }

    setting = config_lookup(&cfgfile, "log");
    if (setting) {
        int rc = parse_config_log(cfg, setting);
        if (rc < 0)
            goto ERR_PARSE;
    }

    config_destroy(&cfgfile);
    return 0;

ERR_FILE:
    ERROR("Could not read configuration file %s", cfgpath);
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfgfile),
            config_error_line(&cfgfile), config_error_text(&cfgfile));
    config_destroy(&cfgfile);
    exit(EXIT_FAILURE);
    return -1;
ERR_PARSE:
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfgfile),
            config_error_line(&cfgfile), config_error_text(&cfgfile));
    config_destroy(&cfgfile);
    return -1;
}

#ifdef __linux__

typedef struct {
    void (*cb)(void *, ...);
    void * args;
} cb_wrapper_args_t;

void cb_wrapper(evutil_socket_t fd, short what, void * arg) {
    cb_wrapper_args_t * cb_wrapper_args = arg;
    cb_wrapper_args->cb(cb_wrapper_args->args);
}

struct event *
loop_register_fd(struct event_base * loop, int fd, void * cb, void * cb_args)
{
    // TODO: not freed
    cb_wrapper_args_t * cb_wrapper_args = malloc(sizeof(cb_wrapper_args_t));
    *cb_wrapper_args = (cb_wrapper_args_t) {
        .cb = cb,
        .args = cb_args,
    };

    evutil_make_socket_nonblocking(fd);
    struct event * event = event_new(loop, fd, EV_READ | EV_PERSIST, cb_wrapper, cb_wrapper_args);
    if (!event)
        goto ERR_EVENT_NEW;

    if (event_add(event, NULL) < 0)
        goto ERR_EVENT_ADD;

    return event;

ERR_EVENT_ADD:
    event_free(event);
ERR_EVENT_NEW:
    return NULL;
}

int
loop_unregister_event(struct event_base * loop, struct event * event)
{
    if (!event)
        return 0;

    event_del(event);
    event_free(event);

    return 0;
}


void * start_dispatch(void * loop_ptr)
{
    struct event_base * loop = (struct event_base *) loop_ptr;
    event_base_dispatch(loop);

    return NULL;
}

#endif /* __linux__ */

int main(int argc, char ** argv)
{
    facemgr_cfg_t * cfg = NULL;
    facemgr_t * facemgr;
#ifdef WITH_THREAD
    pthread_t facemgr_thread;
#endif /* WITH_THREAD */

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


#ifdef WITH_THREAD
    evthread_use_pthreads();
#endif /* WITH_THREAD */

#ifdef __linux__
    /* Event loop */
    loop = event_base_new();
    if (!loop)
        goto ERR_EVENT;

    facemgr_set_event_loop_handler(facemgr, loop, loop_register_fd, loop_unregister_event);
#endif /* __linux__ */

#ifdef __ANDROID__
    facemgr_set_jvm(facemgr, NULL, NULL); // FIXME
#endif /* __ ANDROID__ */

    DEBUG("Bootstrap...");

    if (facemgr_bootstrap(facemgr) < 0 )
        goto ERR_BOOTSTRAP;

#ifdef __linux__
    event_set_log_callback(NULL);

#ifdef WITH_THREAD
    if (pthread_create(&facemgr_thread, NULL, start_dispatch, loop)) {
        fprintf(stderr, "Error creating thread\n");
        return EXIT_FAILURE;
    }
#else
    event_base_dispatch(loop);
#endif /* WITH_THREAD */

#endif /* __linux__ */

#ifdef __APPLE__
    /* Main loop */
    dispatch_main();
#endif /* __APPLE__ */

#ifdef __linux__
#ifdef WITH_THREAD
    for(;;) {
        facemgr_list_faces(facemgr, NULL, NULL);
        sleep(5);
    }
#endif /* WITH_THREAD */
#endif /* __linux__ */

    facemgr_stop(facemgr);

#ifdef __linux__
#ifdef WITH_THREAD
    DEBUG("Waiting for loop to terminate...");
    if(pthread_join(facemgr_thread, NULL)) {
        fprintf(stderr, "Error joining thread\n");
        return EXIT_FAILURE;
    }
    DEBUG("Loop terminated !");
#endif /* WITH_THREAD */
#endif /* __linux__ */

    facemgr_free(facemgr);

    return EXIT_SUCCESS;

ERR_BOOTSTRAP:
#ifdef __linux__
ERR_EVENT:
#endif /* __linux__ */

    facemgr_free(facemgr);
ERR_FACEMGR_CONFIG:
    if (cfg)
        facemgr_cfg_free(cfg);
ERR_FACEMGR:
ERR_FACEMGR_CFG:

ERR_PARSE:
ERR_PATH:
ERR_CMDLINE:
    return EXIT_FAILURE;


}
