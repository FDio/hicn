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
 * @file configurationFile.h
 * @brief Accepts a filename and provides a means to read it into Configuration
 *
 * Reads a configuration file and converts the lines in to configuration
 * commands for use in Configuration.
 *
 * Accepts '#' lines as comments.  Skips blank and whitespace-only lines.
 *
 */

#ifndef configurationFile_h
#define configurationFile_h

#include <hicn/core/forwarder.h>

struct configuration_file;
typedef struct configuration_file ConfigurationFile;

/**
 * Creates a ConfigurationFile to prepare to process the file
 *
 * Prepares the object and opens the file.  Makes sure we can read the file.
 * Does not read the file or process any commands from the file.
 *
 * @param [in] hicn-light An allocated forwarder_t * to configure with the file
 * @param [in] filename The file to use
 *
 * @retval non-null An allocated ConfigurationFile that is readable
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
ConfigurationFile *configurationFile_Create(forwarder_t * *forwarder,
                                            const char *filename);

/**
 * Reads the configuration file line-by-line and issues commands to
 * Configuration
 *
 * Reads the file line by line.  Skips '#' and blank lines.
 *
 * Will stop on the first error.  Lines already processed will not be un-done.
 *
 * @param [in] configFile An allocated ConfigurationFile
 *
 * @retval true The entire files was processed without error.
 * @retval false There was an error in the file.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool configurationFile_Process(ConfigurationFile *configFile);

// void configurationFile_ProcessForwardingStrategies(Configuration * config,
// ConfigurationFile * configFile);

/**
 * Closes the underlying file and releases memory
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in,out] configFilePtr An allocated ConfigurationFile that will be
 * NULL'd as output
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void configurationFile_Release(ConfigurationFile **configFilePtr);

#endif /* defined(configurationFile_h) */
