/* ************************************************************************************************
 * Copyright (C) 2022-2026 Symbiotic Systems Research, LLC
 * All Rights Reserved * Proprietary and confidential
 * 
 * The methods and techniques described herein are considered 
 * trade secrets and/or confidential. Reproduction or distribution, 
 * in whole or in part, is forbidden except by express written 
 * permission of Symbiotic Systems Research, LLC.
 * Please contact <info@symsysresearch.com> for licensing information.
 * 
 * NO WARRANTY, EXPLICIT OR IMPLICIT, IS PROVIDED.
 * In no event shall the author be liable for any claim or damages.
 * 
 * Author: Randall Steck
 * ***********************************************************************************************/

#include "app_common.h"
#include "ardent/ardent_debug.h"

#include <errno.h>

#include "openssl/e_os2.h"

#if defined(OPENSSL_SYS_UNIX)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#elif defined(OPENSSL_SYS_WINDOWS)
#include <windows.h>
#endif

#include "openssl/conf.h"
#include "openssl/err.h"

#define ARDENT_CONFIG_SECTION "ardent_sect"
#define ARDENT_DEBUG_IPC_PATH_KEY "debug-ipc-path"
#define ARDENT_DEBUG_IPC_PATH_MAX 256
#define ARDENT_DEBUG_CONFIG_MAX 1024
#define ARDENT_TEMPLATE_FILE "ardent_trace_template.cnf"

static void print_usage(const char *appname)
{
    fprintf(stderr, "Usage: %s --write-template\n", appname);
    fprintf(stderr, "       %s [--ipc-path <path>] <config-file>\n", appname);
}

static void print_openssl_errors(void)
{
    unsigned long error;

    while ((error = ERR_get_error()) != 0)
        fprintf(stderr, "OpenSSL error: %s\n", ERR_reason_error_string(error));
}

static int get_debug_ipc_path(char *path, size_t path_len)
{
    CONF *config;
    char *default_config = NULL;
    const char *config_file;
    const char *value;
    long error_line = 0;

    config_file = getenv("OPENSSL_CONF");
    if (!config_file || config_file[0] == '\0') {
        default_config = CONF_get1_default_config_file();
        config_file = default_config;
    }

    if (!config_file || config_file[0] == '\0') {
        fprintf(stderr, "Unable to determine the OpenSSL configuration file.\n");
        OPENSSL_free(default_config);
        return 0;
    }

    config = NCONF_new(NULL);
    if (!config) {
        fprintf(stderr, "Unable to allocate OpenSSL configuration.\n");
        print_openssl_errors();
        OPENSSL_free(default_config);
        return 0;
    }

    if (NCONF_load(config, config_file, &error_line) <= 0) {
        fprintf(stderr, "Unable to load OpenSSL configuration '%s' at line %ld.\n",
                config_file, error_line);
        print_openssl_errors();
        NCONF_free(config);
        OPENSSL_free(default_config);
        return 0;
    }

    value = NCONF_get_string(config, ARDENT_CONFIG_SECTION, ARDENT_DEBUG_IPC_PATH_KEY);
    if (!value || value[0] == '\0') {
        fprintf(stderr, "OpenSSL configuration setting [%s] %s is required.\n",
                ARDENT_CONFIG_SECTION, ARDENT_DEBUG_IPC_PATH_KEY);
        ERR_clear_error();
        NCONF_free(config);
        OPENSSL_free(default_config);
        return 0;
    }

    if (strlen(value) >= path_len) {
        fprintf(stderr, "OpenSSL configuration setting [%s] %s is too long.\n",
                ARDENT_CONFIG_SECTION, ARDENT_DEBUG_IPC_PATH_KEY);
        NCONF_free(config);
        OPENSSL_free(default_config);
        return 0;
    }

    strcpy(path, value);
    NCONF_free(config);
    OPENSSL_free(default_config);
    return 1;
}

static int read_config_file(const char *filename, char *config, size_t config_len, size_t *out_len)
{
    FILE *file;
    size_t read_len;

    file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Unable to open configuration file '%s': %s\n", filename, strerror(errno));
        return 0;
    }

    read_len = fread(config, 1, config_len + 1, file);
    if (ferror(file)) {
        fprintf(stderr, "Unable to read configuration file '%s': %s\n", filename, strerror(errno));
        fclose(file);
        return 0;
    }
    fclose(file);

    if (read_len > config_len) {
        fprintf(stderr, "Configuration file '%s' must not exceed %zu bytes.\n", filename, config_len);
        return 0;
    }

    *out_len = read_len;
    return 1;
}

static int write_template(void)
{
    FILE *file;

    file = fopen(ARDENT_TEMPLATE_FILE, "w");
    if (!file) {
        fprintf(stderr, "Unable to create template '%s': %s\n", ARDENT_TEMPLATE_FILE, strerror(errno));
        return 0;
    }

    if (fwrite(template_text, 1, sizeof(template_text) - 1, file) != sizeof(template_text) - 1) {
        fprintf(stderr, "Unable to write template '%s': %s\n", ARDENT_TEMPLATE_FILE, strerror(errno));
        fclose(file);
        return 0;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "Unable to write template '%s': %s\n", ARDENT_TEMPLATE_FILE, strerror(errno));
        return 0;
    }

    return 1;
}

static int trigger_reload(const char *path, const char *config, size_t config_len)
{
#if defined(OPENSSL_SYS_UNIX)
    struct sockaddr_un address;
    int socket_fd;
    char acknowledge;
    size_t sent = 0;

    if (strlen(path) >= sizeof(address.sun_path)) {
        fprintf(stderr, "Debug socket path is too long.\n");
        return 0;
    }

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        fprintf(stderr, "Unable to create debug control socket: %s\n", strerror(errno));
        return 0;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path);

    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(stderr, "Unable to connect to debug socket '%s': %s\n", path, strerror(errno));
        close(socket_fd);
        return 0;
    }

    while (sent < config_len) {
        ssize_t result = send(socket_fd, config + sent, config_len - sent, 0);

        if (result <= 0)
            break;
        sent += (size_t)result;
    }

    if (sent != config_len || shutdown(socket_fd, SHUT_WR) != 0 ||
        recv(socket_fd, &acknowledge, sizeof(acknowledge), 0) != sizeof(acknowledge)) {
        fprintf(stderr, "Unable to send runtime debug configuration: %s\n", strerror(errno));
        close(socket_fd);
        return 0;
    }

    close(socket_fd);
    return acknowledge != 0;
#elif defined(OPENSSL_SYS_WINDOWS)
    HANDLE pipe;
    DWORD written = 0;
    DWORD read = 0;
    char acknowledge;

    pipe = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to connect to debug pipe '%s': system error %lu\n",
                path, (unsigned long)GetLastError());
        return 0;
    }

    if (!WriteFile(pipe, config, (DWORD)config_len, &written, NULL) ||
        written != config_len || !ReadFile(pipe, &acknowledge, sizeof(acknowledge), &read, NULL) ||
        read != sizeof(acknowledge)) {
        fprintf(stderr, "Unable to send runtime debug configuration: system error %lu\n",
                (unsigned long)GetLastError());
        CloseHandle(pipe);
        return 0;
    }

    CloseHandle(pipe);
    return acknowledge != 0;
#else
    (void)path;
    (void)config;
    (void)config_len;
    fprintf(stderr, "Runtime debug reload is unsupported on this platform.\n");
    return 0;
#endif
}

int main(int argc, char *argv[])
{
    char debug_ipc_path[ARDENT_DEBUG_IPC_PATH_MAX];
    char config[ARDENT_DEBUG_CONFIG_MAX + 1];
    const char *debug_ipc_path_arg = NULL;
    const char *config_file = NULL;
    size_t config_len;
    int index;

    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--write-template") == 0) {
            if (debug_ipc_path_arg || config_file) {
                print_usage(argv[0]);
                return 1;
            }
            return write_template() ? 0 : 1;
        } else if (strcmp(argv[index], "--ipc-path") == 0) {
            if (debug_ipc_path_arg || index + 1 >= argc || argv[index + 1][0] == '\0') {
                print_usage(argv[0]);
                return 1;
            }
            debug_ipc_path_arg = argv[++index];
        } else if (argv[index][0] != '-' && !config_file) {
            config_file = argv[index];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!config_file) {
        fprintf(stderr, "No configuration file specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (debug_ipc_path_arg) {
        if (strlen(debug_ipc_path_arg) >= sizeof(debug_ipc_path)) {
            fprintf(stderr, "Debug path is too long.\n");
            return 1;
        }
        strcpy(debug_ipc_path, debug_ipc_path_arg);
    } else if (!get_debug_ipc_path(debug_ipc_path, sizeof(debug_ipc_path))) {
        fprintf(stderr, "Specify --ipc-path or configure [%s] %s in OPENSSL_CONF.\n",
                ARDENT_CONFIG_SECTION, ARDENT_DEBUG_IPC_PATH_KEY);
        return 1;
    }

    if (!read_config_file(config_file, config, ARDENT_DEBUG_CONFIG_MAX, &config_len))
        return 1;

    if (!trigger_reload(debug_ipc_path, config, config_len)) {
        fprintf(stderr, "Runtime debug configuration was rejected.\n");
        return 1;
    }

    return 0;
}