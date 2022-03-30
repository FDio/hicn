/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * \file cfg_file.h
 * \brief Configuration file parsing
 */

#ifndef FACEMGR_CFG_FILE_H
#define FACEMGR_CFG_FILE_H

#include <hicn/facemgr/cfg.h>

/**
 * \brief Probe for the configuration file location
 * \param [in] f - File name
 * \return 0 in case of success, -1 otherwise.
 */
int probe_cfgfile(char* f);

/**
 * \brief Parses the provided configuration file into the facemgr configuration
 * data structure.
 * \param [in] cfgpath - Path to the configuration file
 * \param [out] cfg - Pre-allocated configuration data structure
 * \return 0 in case of success, -1 otherwise.
 */
int parse_config_file(const char* cfgpath, facemgr_cfg_t* cfg);

#endif /* FACEMGR_CFG_FILE_H */
