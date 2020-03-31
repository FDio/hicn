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

#ifndef _WIN32
#include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <string.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_List.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <hicn/config/configuration.h>
#include <hicn/config/configuration_file.h>
#include <hicn/config/controlRoot.h>
#include <hicn/config/controlState.h>
#include <hicn/util/log.h>

struct configuration_file {
    forwarder_t *forwarder;
    char *filename;
    FILE *fh;

    size_t linesRead;

    // our custom state machine.
    ControlState *control_state;
};

/*
 * Called by a command to dispatch the correct command
 */
uint8_t *
_write_read(ControlState *state, uint8_t * packet)
{
    assert(state);
    assert(packet);

    configuration_file_t *configFile =
        (configuration_file_t *)controlState_GetUserdata(state);

    Configuration * config = forwarder_get_configuration(configFile->forwarder);
    command_type_t command_type =
        command_type_from_uchar(((cmd_header_t*)packet)->commandID);

    return configuration_dispatch_command(config, command_type, packet, 0);
}

/**
 * Removes leading whitespace (space + tab).
 *
 * If the string is all whitespace, the return value will point to the
 * terminating '\0'.
 *
 * @param [in] str A null-terminated c-string
 *
 * @retval non-null A pointer in to string of the first non-whitespace
 *
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
static char *
_stripLeadingWhitespace(char *str)
{
    while (isspace(*str))
        str++;
    return str;
}

/**
 * Removes trailing whitespace
 *
 * Inserts a NULL after the last non-whitespace character, modiyfing the input
 * string.
 *
 * @param [in] str A null-terminated c-string
 *
 * @return non-null A pointer to the input string
 *
 * Example:
 * @code
 * {
 *     <#example#>
 * }
 * @endcode
 */
static char *
_stripTrailingWhitespace(char *str)
{
    char *p = str + strlen(str) - 1;
    while (p > str && isspace(*p))
        p--;

    // cap it.  If no whitespace, p+1 == str + strlen(str), so will overwrite the
    // current null.  If all whitespace p+1 == str+1.  For an empty string, p+1 =
    // str.
    *(p + 1) = 0;

    // this does not catch the case where the entire string is whitespace
    if (p == str && isspace(*p))
        *p = 0;

    return str;
}

/**
 * Removed leading and trailing whitespace
 *
 * Modifies the input string (may add a NULL at the end).  Will return
 * a pointer to the first non-whitespace character or the terminating NULL.
 *
 * @param [in] str A null-terminated c-string
 *
 * @return non-null A pointer in to the input string
 *
 * Example:
 * @code
 * {
 *     <#example#>
 * }
 * @endcode
 */
static char *
_trim(char *str)
{
    return _stripTrailingWhitespace(_stripLeadingWhitespace(str));
}

/**
 * Parse a string in to a PARCList with one word per element
 *
 * The string passed will be modified by inserting NULLs after each token.
 *
 * @param [in] str A c-string (will be modified)
 *
 * @retval non-null A PARCList where each item is a single word
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
static PARCList *
_parseArgs(char *str)
{
    PARCList *list =
        parcList(parcArrayList_Create(NULL), PARCArrayListAsPARCList);

    const char delimiters[] = " \t";

    char *token;
    token = strtok(str, delimiters);
    while (token != NULL) {
        if (strlen(token) > 0) {
            parcList_Add(list, strdup(token));
        }
        token = strtok(NULL, delimiters);
    }
    return list;
}

// =============================================================

configuration_file_t *
configuration_file_create(forwarder_t * forwarder, const char * filename)
{
    assert(forwarder);
    assert(filename);

    configuration_file_t *cfg = malloc(sizeof(configuration_file_t));
    if (!cfg)
        return NULL;

    cfg->linesRead = 0;
    cfg->forwarder = forwarder;
    cfg->filename = strdup(filename);
    assert(cfg->filename);

    // setup the control state for the command parser: last parameter NULL
    // because
    // write_read still not implemented from configuration file.
    cfg->control_state = controlState_Create(cfg, _write_read, false,
                SRV_CTRL_IP, SRV_CTRL_PORT);

    // we do not register Help commands
    controlState_RegisterCommand(cfg->control_state, controlRoot_Create(cfg->control_state));

    // open the file and make sure we can read it
    cfg->fh = fopen(cfg->filename, "r");

    if (cfg->fh) {
        DEBUG("Open config file %s", cfg->filename);
    } else {
        ERROR("Could not open config file %s: (%d) %s", cfg->filename, errno, strerror(errno));

        // failure cleanup the object -- this nulls it so final return null be
        // NULL
        configuration_file_free(cfg);
    }
    return cfg;
}

bool
configuration_file_process(configuration_file_t *configFile)
{
    assert(configFile);

    // default to a "true" return value and only set to false if we encounter an
    // error.
    bool success = true;

#define BUFFERLEN 2048
    char buffer[BUFFERLEN];

    configFile->linesRead = 0;

    // always clear errors and fseek to start of file in case we get called
    // multiple times.
    clearerr(configFile->fh);
    rewind(configFile->fh);

    while (success && fgets(buffer, BUFFERLEN, configFile->fh) != NULL) {
        configFile->linesRead++;

        char *stripedBuffer = _trim(buffer);
        if (strlen(stripedBuffer) > 0) {
            if (stripedBuffer[0] != '#') {
                // not empty and not a comment

                // _parseArgs will modify the string
                char *copy =
                    parcMemory_StringDuplicate(stripedBuffer, strlen(stripedBuffer));
                PARCList *args = _parseArgs(copy);
                CommandReturn result =
                    controlState_DispatchCommand(configFile->control_state, args);

                // we ignore EXIT from the configuration file
                if (result == CommandReturn_Failure) {
                    ERROR("Error on input file %s line %d: %s",
                            configFile->filename, configFile->linesRead,
                            stripedBuffer);
                    success = false;
                }
                for(int i = 0; i < parcList_Size(args); i++){
                    free(parcList_GetAtIndex(args, i));
                }
                parcList_Release(&args);
                parcMemory_Deallocate((void **)&copy);
            }
        }
    }

    if (ferror(configFile->fh)) {
        ERROR("Error on input file %s line %d: (%d) %s",
        configFile->filename, configFile->linesRead, errno,
        strerror(errno));
        success = false;
    }

    return success;
}

void
configuration_file_free(configuration_file_t * cfg)
{
    free(cfg->filename);
    if (cfg->fh)
        fclose(cfg->fh);
    controlState_Destroy(&cfg->control_state);
    free(cfg);
}
