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
 * @file configuration_file.h
 * @brief Accepts a filename and provides a means to read it into Configuration
 *
 * Reads a configuration file and converts the lines in to configuration
 * commands for use in Configuration.
 *
 * Accepts '#' lines as comments.  Skips blank and whitespace-only lines.
 *
 */

#ifndef configuration_file_h
#define configuration_file_h

#include <hicn/core/forwarder.h>

/**
 * Configure hicn-light by reading a configuration file line-by-line and
 * issueing commands to the forwarder.
 *
 * The configuration file is a set of lines, just like used in hicnLightControl.
 * You need to have "add listener" lines in the file to receive connections. No
 * default listeners are configured.
 *
 * This function reads the file line by line, skipping '#' and blank lines, and
 * will stop on the first error. Lines already processed will not be un-done.
 *
 * @param[in] forwarder An allocated forwarder_t
 * @param[in] filename The path to the configuration file
 *
 * @retval true The entire files was processed without error.
 * @retval false There was an error in the file.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool configuration_file_process(forwarder_t* forwarder, const char* filename);

#endif /* defined(configuration_file_h) */
