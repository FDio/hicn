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
 * \file cfg_file.c
 * \brief Implementation of configuration file parsing
 */

#include <unistd.h> // access
#include <libconfig.h>

#include <hicn/ctrl/route.h>

#include "cfg_file.h"

#define ARRAYSIZE(x) (sizeof(x)/sizeof(*x))

static const char * DEFAULT_CFGFILES[] = {
    "/etc/facemgr.conf",
    "~/facemgr.conf",
};

int
probe_cfgfile(char * f)
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
        int rc = facemgr_cfg_set_ipv4(cfg, !disable_ipv4);
        if (rc < 0)
            goto ERR;
    }

    /* - disable ipv6 */

    int disable_ipv6;
    if (config_setting_lookup_bool(setting, "disable_ipv6",
                &disable_ipv6)) {
        int rc = facemgr_cfg_set_ipv6(cfg, !disable_ipv6);
        if (rc < 0)
            goto ERR;
    }

    /* - overlay */
    config_setting_t *overlay = config_setting_get_member(setting, "overlay");
    if (overlay) {

        /* ipv4 */
        config_setting_t *overlay_v4 = config_setting_get_member(overlay, "ipv4");
        if (overlay_v4) {
            const char * local_addr_str, * remote_addr_str;
            ip_address_t local_addr = IP_ADDRESS_EMPTY;
            ip_address_t remote_addr = IP_ADDRESS_EMPTY;
            ip_address_t * local_addr_p = NULL;
            ip_address_t * remote_addr_p = NULL;
            int local_port = 0;
            int remote_port = 0;

            if (config_setting_lookup_string(overlay_v4, "local_addr", &local_addr_str)) {
                if (ip_address_pton(local_addr_str, &local_addr) < 0) {
                    ERROR("Error parsing v4 local addr");
                    goto ERR;
                }
                local_addr_p = &local_addr;
            }

            if (config_setting_lookup_int(overlay_v4, "local_port", &local_port)) {
                if (!IS_VALID_PORT(local_port))
                    goto ERR;
            }

            if (config_setting_lookup_string(overlay_v4, "remote_addr", &remote_addr_str)) {
                if (ip_address_pton(remote_addr_str, &remote_addr) < 0) {
                    ERROR("Error parsing v4 remote addr");
                    goto ERR;
                }
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
            ip_address_t local_addr = IP_ADDRESS_EMPTY;
            ip_address_t remote_addr = IP_ADDRESS_EMPTY;
            ip_address_t * local_addr_p = NULL;
            ip_address_t * remote_addr_p = NULL;
            int local_port = 0;
            int remote_port = 0;

            if (config_setting_lookup_string(overlay_v6, "local_addr", &local_addr_str)) {
                if (ip_address_pton(local_addr_str, &local_addr) < 0) {
                    ERROR("Error parsing v6 local addr");
                    goto ERR;
                }
                local_addr_p = &local_addr;
            }

            if (config_setting_lookup_int(overlay_v6, "local_port", &local_port)) {
                if (!IS_VALID_PORT(local_port))
                    goto ERR;
            }

            if (config_setting_lookup_string(overlay_v6, "remote_addr", &remote_addr_str)) {
                if (ip_address_pton(remote_addr_str, &remote_addr) < 0) {
                    ERROR("Error parsing v6 remote addr");
                    goto ERR;
                }
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
                ip_address_t local_addr = IP_ADDRESS_EMPTY;
                ip_address_t remote_addr = IP_ADDRESS_EMPTY;
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
                ip_address_t local_addr = IP_ADDRESS_EMPTY;
                ip_address_t remote_addr = IP_ADDRESS_EMPTY;
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

int parse_config_static_facelets(facemgr_cfg_t * cfg, config_setting_t * setting)
{
    int count = config_setting_length(setting);
    for (unsigned i = 0; i < count; ++i) {
        config_setting_t * static_setting = config_setting_get_elem(setting, i);

        const char *face_type_str;
        facemgr_face_type_t face_type;
        const char * family_str;
        int family;
        const char * remote_addr_str;
        ip_address_t remote_addr = IP_ADDRESS_EMPTY;
        int remote_port = 0;
        const char * interface_name;
        const char * interface_type_str;

        facelet_t * facelet = facelet_create();

        /* Face type */
        if (config_setting_lookup_string(static_setting, "face_type", &face_type_str)) {
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
                goto ERR_FACELET;
            }

            int rc = facelet_set_face_type(facelet, face_type);
            if (rc < 0)
                goto ERR_FACELET;
        }

        /* Family */
        if (config_setting_lookup_string(static_setting, "family", &family_str)) {
            if (strcasecmp(family_str, "AF_INET") == 0) {
                family = AF_INET;
            } else
            if (strcasecmp(family_str, "AF_INET6") == 0) {
                family = AF_INET6;
            } else {
                ERROR("Invalid family in section 'static', items #%d", i+1);
                goto ERR_FACELET;
            }
            int rc = facelet_set_family(facelet, family);
            if (rc < 0)
                goto ERR_FACELET;
        }

        /* Remote address */
        if (config_setting_lookup_string(static_setting, "remote_addr", &remote_addr_str)) {
            if (ip_address_pton(remote_addr_str, &remote_addr) < 0) {
                ERROR("Error parsing v4 remote addr");
                goto ERR_FACELET;
            }

            int rc = facelet_set_remote_addr(facelet, remote_addr);
            if (rc < 0)
                goto ERR_FACELET;
        }

        /* Remote port */
        if (config_setting_lookup_int(static_setting, "remote_port", &remote_port)) {
            if (!IS_VALID_PORT(remote_port))
                goto ERR_FACELET;
            int rc = facelet_set_remote_port(facelet, remote_port);
            if (rc < 0)
                goto ERR_FACELET;
        }

        /* Interface name */
        if (config_setting_lookup_string(static_setting, "interface_name", &interface_name)) {
            netdevice_t netdevice;
            /* Warning: interface might not exist when we create the facelet */
            snprintf(netdevice.name, IFNAMSIZ, "%s", interface_name);
            netdevice.index = 0;
            int rc = facelet_set_netdevice(facelet, netdevice);
            if (rc < 0)
                goto ERR_FACELET;
        }

        /* Interface type */
        netdevice_type_t interface_type = NETDEVICE_TYPE_UNDEFINED;
        if (config_setting_lookup_string(static_setting, "interface_type", &interface_type_str)) {
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
                goto ERR_FACELET;
            }

            int rc = facelet_set_netdevice_type(facelet, interface_type);
            if (rc < 0)
                goto ERR_FACELET;
        }

        /* Routes */
        config_setting_t * routes_static_setting = config_setting_get_member(static_setting, "routes");
        if (routes_static_setting) {
            /* ... */
            int count_routes = config_setting_length(routes_static_setting);
            for (unsigned j = 0; j < count_routes; ++j) {
                config_setting_t * route_static_setting = config_setting_get_elem(routes_static_setting, j);

                const char * prefix_str;
                ip_prefix_t prefix;
                int cost = 0; /* default */

                if (config_setting_lookup_string(route_static_setting, "prefix", &prefix_str)) {
                    if (ip_prefix_pton(prefix_str, &prefix) < 0) {
                        ERROR("Error parsing prefix in route #%d, rule #%d", j, i);
                        goto ERR_FACELET;
                    }
                } else {
                    ERROR("Cannot add route without prefix");
                    goto ERR_FACELET;
                }

                config_setting_lookup_int(static_setting, "cost", &cost);

                hicn_route_t * route = hicn_route_create(&prefix, 0, cost);
                if (!route) {
                    ERROR("Could not create hICN route");
                    goto ERR_FACELET;
                }

                int rc = facelet_add_route(facelet, route);
                if (rc < 0) {
                    ERROR("Could not add route to facelet");
                    goto ERR_ROUTE;
                }

                continue;

ERR_ROUTE:
                hicn_route_free(route);
                goto ERR_FACELET;
            }
        }

        if (facemgr_cfg_add_static_facelet(cfg, facelet) < 0) {
            ERROR("Could not add static facelet to configuration");
            goto ERR_FACELET;
        }

        continue;

ERR_FACELET:
        facelet_free(facelet);
        return -1;

        }
    return 0;
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

    setting = config_lookup(&cfgfile, "static");
    if (setting) {
        int rc = parse_config_static_facelets(cfg, setting);
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

