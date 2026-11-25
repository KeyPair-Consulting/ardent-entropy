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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/e_os2.h"

#if defined(OPENSSL_SYS_UNIX)
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
#elif defined(OPENSSL_SYS_WINDOWS)
# include <windows.h>
# include <direct.h>
#endif

#include "openssl/conf.h"
#include "openssl/err.h"

#define ARDENT_CONFIG_SECTION "ardent_sect"
#define ARDENT_DEBUG_IPC_PATH_KEY "debug-ipc-path"
#define ARDENT_DEBUG_IPC_PATH_MAX 256
#define ARDENT_DEBUG_CONFIG_MAX 1024

#define TEST_FILE_TRACE            "test_trace.log"
#define TEST_FILE_PROFILE_SAMPLE   "test_profile_sample.log"
#define TEST_FILE_PROFILE_INTERVAL "test_profile_interval.log"
#define TEST_FILE_PROFILE_CSV      "test_profile_csv.log"
#define TEST_FILE_BOTH             "test_both.log"
#define TEST_FILE_BOTH_TRACE       "test_both_trace.log"
#define TEST_FILE_BOTH_PROFILE     "test_both_profile.log"
#define TEST_FILE_SUMMARY_BOTH     "test_summary_both.log"
#define TEST_FILE_SUMMARY_TRACE    "test_summary_trace.log"
#define TEST_FILE_SUMMARY_PROFILE  "test_summary_profile.log"

typedef struct {
    char trace_file[ARDENT_DEBUG_IPC_PATH_MAX];
    char profile_file[ARDENT_DEBUG_IPC_PATH_MAX];
    const char *test_name;
} RUNTIME_TEST_FILES;

enum {
    TEST_TRACE_ONLY,
    TEST_PROFILE_SAMPLE_ONLY,
    TEST_PROFILE_SUMMARY_ONLY,
    TEST_PROFILE_CSV,
    TEST_BOTH_SAMPLE_SHARED,
    TEST_BOTH_SAMPLE_SEPARATE,
    TEST_BOTH_SUMMARY_SHARED,
    TEST_BOTH_SUMMARY_SEPARATE,
    TEST_INVALID_CONFIG,
    TEST_DEBUG_RESET,
    TEST_COUNT
};

static RUNTIME_TEST_FILES test_files[TEST_COUNT] = {
    [TEST_TRACE_ONLY] = {{0}, {0}, "Test 1: Trace Only Configuration"},
    [TEST_PROFILE_SAMPLE_ONLY] = {{0}, {0}, "Test 2: Profile Sample Only (each-sample = 1, interval = 0)"},
    [TEST_PROFILE_SUMMARY_ONLY] = {{0}, {0}, "Test 3: Profile Summary Only (each-sample = 0, interval = N)"},
    [TEST_PROFILE_CSV] = {{0}, {0}, "Test 4: Profile CSV (each-sample and interval)"},
    [TEST_BOTH_SAMPLE_SHARED] = {{0}, {0}, "Test 5: Combined Trace & Profile Configuration"},
    [TEST_BOTH_SAMPLE_SEPARATE] = {{0}, {0}, "Test 6: Combined Trace & Profile to Separate Files"},
    [TEST_BOTH_SUMMARY_SHARED] = {{0}, {0}, "Test 7: Combined Trace & Profile Summary to Same File"},
    [TEST_BOTH_SUMMARY_SEPARATE] = {{0}, {0}, "Test 8: Combined Trace & Profile Summary to Separate Files"},
    [TEST_INVALID_CONFIG] = {{0}, {0}, "Test 9: Invalid Configuration Rejection"},
    [TEST_DEBUG_RESET] = {{0}, {0}, "Test 10: Runtime Debug Reset to Full Off"}
};

/* ************************************************************************************************
 * ************************************************************************************************
 * USAGE
 * ************************************************************************************************
 * ***********************************************************************************************/

static void print_usage(const char* appname)
{
	const int indent = 22;
	printf("%s --interval <integer> [--ipc-path <path>] [--preserve]\n", appname);
	printf("\n");
	printf("Test and validate ARDENT runtime debug reconfiguration via IPC (UNIX domain socket or\n");
	printf("Windows named pipe). Designed to run alongside an active instance of 'ardent_rand --interval <sec>'\n");
	printf("to verify dynamic reconfiguration of tracing, profiling, and full debug reset.\n");
	printf("\n");
	printf("Arguments:\n");
	printf("%-*s%s\n", indent, "--interval <integer>", "Specify the sleep interval (in seconds) used by the running");
	printf("%-*s%s\n", indent, "",                  "instance of ardent_rand (required)");
	printf("%-*s%s\n", indent, "--ipc-path <path>",   "Specify the IPC socket or named pipe path to use instead of");
	printf("%-*s%s\n", indent, "",                  "reading '" ARDENT_DEBUG_IPC_PATH_KEY "' from the OpenSSL configuration");
	printf("%-*s%s\n", indent, "--preserve",          "Preserve test output log files on exit for inspection");
	printf("%-*s%s\n", indent, "",                  "(default: delete all temporary log files upon completion)");
	printf("\n");
}

static void sleep_seconds(unsigned int sec)
{
#if defined(OPENSSL_SYS_WINDOWS)
    Sleep((DWORD)(sec * 1000));
#else
    sleep(sec);
#endif
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
        fprintf(stderr, "Unable to determine OpenSSL configuration file.\n");
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

static int get_local_dir(char *dir, size_t dir_len)
{
#if defined(OPENSSL_SYS_WINDOWS)
    if (_getcwd(dir, (int)dir_len) == NULL)
        return 0;
#else
    if (getcwd(dir, dir_len) == NULL)
        return 0;
#endif
    return 1;
}

static int send_reload_config(const char *path, const char *config, size_t config_len)
{
#if defined(OPENSSL_SYS_UNIX)
    struct sockaddr_un address;
    int socket_fd;
    char acknowledge = 0;
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
        close(socket_fd);
        return 0;
    }

    close(socket_fd);
    return acknowledge != 0;
#elif defined(OPENSSL_SYS_WINDOWS)
    HANDLE pipe;
    DWORD written = 0;
    DWORD read = 0;
    char acknowledge = 0;

    pipe = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to connect to debug pipe '%s': system error %lu\n",
                path, (unsigned long)GetLastError());
        return 0;
    }

    if ((config_len > 0 && (!WriteFile(pipe, config, (DWORD)config_len, &written, NULL) || written != config_len)) ||
        !ReadFile(pipe, &acknowledge, sizeof(acknowledge), &read, NULL) || read != sizeof(acknowledge)) {
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

typedef enum {
    EXPECT_NONE = 0,
    EXPECT_TRACE_ONLY,
    EXPECT_PROFILE_SAMPLE_ONLY,
    EXPECT_PROFILE_SUMMARY_ONLY,
    EXPECT_PROFILE_ANY_ONLY,
    EXPECT_BOTH,
    EXPECT_BOTH_SUMMARY,
    EXPECT_PROFILE_CSV
} validation_type_t;

static int validate_log_file(const char *filename, validation_type_t expected)
{
    FILE *fp;
    char line[512];
    int has_banner = 0;
    int has_trace_records = 0;
    int has_profile_sample_records = 0;
    int has_profile_summary_records = 0;
    int has_profile_csv_header = 0;
    int has_profile_csv_sample = 0;
    int has_profile_csv_summary = 0;

    fp = fopen(filename, "r");
    if (!fp) {
        if (expected == EXPECT_NONE)
            return 1;
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "=== ARDENT Debug Output ==="))
            has_banner = 1;
        if (strstr(line, "Start:") && strstr(line, "UTC"))
            has_banner = 1;
        if (strcmp(line, "Type,Source,Size (B),Last (us),Mean (us),Window (us),Min (us),Max (us),Count\n") == 0)
            has_profile_csv_header = 1;

        /* Trace records contain timestamp bracket and module/submodule tags */
        if (line[0] == '[' && (strstr(line, "SEED") || strstr(line, "THREAD") ||
            strstr(line, "SINK") || strstr(line, "ARDENT") || strstr(line, "PROVIDER") ||
            strstr(line, "RAND") || strstr(line, "JITTER") || strstr(line, "RDRAND") ||
            strstr(line, "RDSEED") || strstr(line, "OSRAND") || strstr(line, "EXTERN"))) {
            if (!strstr(line, "Start:"))
                has_trace_records = 1;
        }

        /* Profile records contain PROFILE label (per-sample) or PROFILE-SUMMARY (interval reset) */
        if (strstr(line, "PROF-SUMMARY")) {
            has_profile_summary_records = 1;
        } else if (strstr(line, "PROF-SAMPLE")) {
            has_profile_sample_records = 1;
        }
        if (strncmp(line, "PROF-SAMPLE,", strlen("PROF-SAMPLE,")) == 0)
            has_profile_csv_sample = 1;
        if (strncmp(line, "PROF-SUMMARY,", strlen("PROF-SUMMARY,")) == 0)
            has_profile_csv_summary = 1;
    }
    fclose(fp);

    switch (expected) {
    case EXPECT_NONE:
        return (!has_trace_records && !has_profile_sample_records && !has_profile_summary_records);
    case EXPECT_TRACE_ONLY:
        return (has_banner && has_trace_records && !has_profile_sample_records && !has_profile_summary_records);
    case EXPECT_PROFILE_SAMPLE_ONLY:
        return (has_banner && has_profile_sample_records && !has_trace_records);
    case EXPECT_PROFILE_SUMMARY_ONLY:
        return (has_banner && has_profile_summary_records && !has_trace_records);
    case EXPECT_PROFILE_ANY_ONLY:
        return (has_banner && (has_profile_sample_records || has_profile_summary_records) && !has_trace_records);
    case EXPECT_BOTH:
        return (has_banner && has_trace_records && (has_profile_sample_records || has_profile_summary_records));
    case EXPECT_BOTH_SUMMARY:
        return (has_banner && has_trace_records && has_profile_summary_records && !has_profile_sample_records);
    case EXPECT_PROFILE_CSV:
        return (has_banner && has_profile_csv_header && has_profile_csv_sample &&
            has_profile_csv_summary && !has_trace_records);
    default:
        return 0;
    }
}

static void cleanup_test_files(int preserve)
{
    int i;

    if (preserve) {
        printf("\nPreserving test log files:\n");
        for (i = 0; i < TEST_COUNT; ++i) {
            if (test_files[i].trace_file[0] != '\0')
                printf("  - %s\n", test_files[i].trace_file);
            if (test_files[i].profile_file[0] != '\0' &&
                strcmp(test_files[i].trace_file, test_files[i].profile_file) != 0) {
                printf("  - %s\n", test_files[i].profile_file);
            }
        }
        return;
    }

    for (i = 0; i < TEST_COUNT; ++i) {
        if (test_files[i].trace_file[0] != '\0')
            remove(test_files[i].trace_file);
        if (test_files[i].profile_file[0] != '\0' &&
            strcmp(test_files[i].trace_file, test_files[i].profile_file) != 0) {
            remove(test_files[i].profile_file);
        }
    }
}

static void set_test_file(char *path, const char *directory, const char *filename)
{
    if (!filename)
        return;

    strcpy(path, directory);
    strcat(path, "/");
    strcat(path, filename);
}

int main(int argc, char *argv[])
{
    char debug_ipc_path[ARDENT_DEBUG_IPC_PATH_MAX] = {0};
    char local_dir[ARDENT_DEBUG_IPC_PATH_MAX] = {0};
    const char *debug_ipc_path_arg = NULL;
    int interval = 0;
    int preserve = 0;
    int index;
    int test_pass[TEST_COUNT] = {0};

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--interval") == 0) {
            if (index + 1 >= argc || argv[index + 1][0] == '-') {
                print_usage(argv[0]);
                return 1;
            }
            interval = atoi(argv[++index]);
        } else if (strcmp(argv[index], "--ipc-path") == 0) {
            if (index + 1 >= argc || argv[index + 1][0] == '\0') {
                print_usage(argv[0]);
                return 1;
            }
            debug_ipc_path_arg = argv[++index];
        } else if (strcmp(argv[index], "--preserve") == 0) {
            preserve = 1;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (interval <= 0) {
        fprintf(stderr, "Error: --interval must be a positive integer (seconds).\n");
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

    if (!get_local_dir(local_dir, sizeof(local_dir))) {
        fprintf(stderr, "Error: unable to determine current working directory: %s\n", strerror(errno));
        return 1;
    }

    if (strlen(local_dir) + 32 >= sizeof(test_files[0].trace_file)) {
        fprintf(stderr, "Error: current working directory path is too long.\n");
        return 1;
    }

    set_test_file(test_files[TEST_TRACE_ONLY].trace_file, local_dir, TEST_FILE_TRACE);
    set_test_file(test_files[TEST_PROFILE_SAMPLE_ONLY].profile_file, local_dir, TEST_FILE_PROFILE_SAMPLE);
    set_test_file(test_files[TEST_PROFILE_SUMMARY_ONLY].profile_file, local_dir, TEST_FILE_PROFILE_INTERVAL);
    set_test_file(test_files[TEST_PROFILE_CSV].profile_file, local_dir, TEST_FILE_PROFILE_CSV);
    set_test_file(test_files[TEST_BOTH_SAMPLE_SHARED].trace_file, local_dir, TEST_FILE_BOTH);
    set_test_file(test_files[TEST_BOTH_SAMPLE_SHARED].profile_file, local_dir, TEST_FILE_BOTH);
    set_test_file(test_files[TEST_BOTH_SAMPLE_SEPARATE].trace_file, local_dir, TEST_FILE_BOTH_TRACE);
    set_test_file(test_files[TEST_BOTH_SAMPLE_SEPARATE].profile_file, local_dir, TEST_FILE_BOTH_PROFILE);
    set_test_file(test_files[TEST_BOTH_SUMMARY_SHARED].trace_file, local_dir, TEST_FILE_SUMMARY_BOTH);
    set_test_file(test_files[TEST_BOTH_SUMMARY_SHARED].profile_file, local_dir, TEST_FILE_SUMMARY_BOTH);
    set_test_file(test_files[TEST_BOTH_SUMMARY_SEPARATE].trace_file, local_dir, TEST_FILE_SUMMARY_TRACE);
    set_test_file(test_files[TEST_BOTH_SUMMARY_SEPARATE].profile_file, local_dir, TEST_FILE_SUMMARY_PROFILE);

    /* Clean up any preexisting files from prior runs before testing */
    cleanup_test_files(0);

    printf("Connecting to debug IPC at '%s'...\n", debug_ipc_path);
    printf("Local test files directory: '%s'\n", local_dir);
    printf("Configured test wait interval: %d seconds per step.\n\n", interval + 1);

    /* ------------------------------------------------------------- */
    /* Test 1: Trace Only Configuration                              */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[trace]\n"
            "file = %s\n"
            "seed = 1\n"
            "sink = 1\n"
            "thread = 1\n"
            "lazy-write = 0\n",
            test_files[TEST_TRACE_ONLY].trace_file);

        printf("Executing %s...\n", test_files[TEST_TRACE_ONLY].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval + 1));
            if (validate_log_file(test_files[TEST_TRACE_ONLY].trace_file, EXPECT_TRACE_ONLY))
                test_pass[TEST_TRACE_ONLY] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 2: Profile Sample Only (each-sample = 1, interval = 0)   */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[profile]\n"
            "file = %s\n"
            "interval = 0\n"
            "each-sample = 1\n"
            "format-csv = 0\n",
            test_files[TEST_PROFILE_SAMPLE_ONLY].profile_file);

        printf("Executing %s...\n", test_files[TEST_PROFILE_SAMPLE_ONLY].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval + 1));
            if (validate_log_file(test_files[TEST_PROFILE_SAMPLE_ONLY].profile_file, EXPECT_PROFILE_SAMPLE_ONLY))
                test_pass[TEST_PROFILE_SAMPLE_ONLY] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 3: Profile Summary Only (each-sample = 0, interval = 3N) */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[profile]\n"
            "file = %s\n"
            "interval = %d\n"
            "each-sample = 0\n"
            "format-csv = 0\n",
            test_files[TEST_PROFILE_SUMMARY_ONLY].profile_file,
            interval * 3);

        printf("Executing %s...\n", test_files[TEST_PROFILE_SUMMARY_ONLY].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            /* Wait for interval reset period + margin */
            sleep_seconds((unsigned int)(interval * 3 + 2));
            if (validate_log_file(test_files[TEST_PROFILE_SUMMARY_ONLY].profile_file, EXPECT_PROFILE_SUMMARY_ONLY))
                test_pass[TEST_PROFILE_SUMMARY_ONLY] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 4: Profile CSV (each-sample = 1, interval = 3N)         */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[profile]\n"
            "file = %s\n"
            "interval = %d\n"
            "each-sample = 1\n"
            "format-csv = 1\n",
            test_files[TEST_PROFILE_CSV].profile_file,
            interval * 3);

        printf("Executing %s...\n", test_files[TEST_PROFILE_CSV].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval * 3 + 2));
            if (validate_log_file(test_files[TEST_PROFILE_CSV].profile_file, EXPECT_PROFILE_CSV))
                test_pass[TEST_PROFILE_CSV] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 5: Combined Trace & Profile Configuration               */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[trace]\n"
            "file = %s\n"
            "seed = 1\n"
            "sink = 1\n"
            "thread = 1\n"
            "lazy-write = 0\n"
            "\n"
            "[profile]\n"
            "file = %s\n"
            "interval = %d\n"
            "each-sample = 1\n"
            "format-csv = 0\n",
            test_files[TEST_BOTH_SAMPLE_SHARED].trace_file,
            test_files[TEST_BOTH_SAMPLE_SHARED].profile_file,
            interval * 3);

        printf("Executing %s...\n", test_files[TEST_BOTH_SAMPLE_SHARED].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval * 3 + 2));
            if (validate_log_file(test_files[TEST_BOTH_SAMPLE_SHARED].trace_file, EXPECT_BOTH))
                test_pass[TEST_BOTH_SAMPLE_SHARED] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 6: Combined Trace & Profile to Separate Files            */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[trace]\n"
            "file = %s\n"
            "seed = 1\n"
            "sink = 1\n"
            "thread = 1\n"
            "lazy-write = 0\n"
            "\n"
            "[profile]\n"
            "file = %s\n"
            "interval = %d\n"
            "each-sample = 1\n"
            "format-csv = 0\n",
            test_files[TEST_BOTH_SAMPLE_SEPARATE].trace_file,
            test_files[TEST_BOTH_SAMPLE_SEPARATE].profile_file,
            interval * 3);

        printf("Executing %s...\n", test_files[TEST_BOTH_SAMPLE_SEPARATE].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval * 3 + 2));
            if (validate_log_file(test_files[TEST_BOTH_SAMPLE_SEPARATE].trace_file, EXPECT_TRACE_ONLY) &&
                validate_log_file(test_files[TEST_BOTH_SAMPLE_SEPARATE].profile_file, EXPECT_PROFILE_ANY_ONLY)) {
                test_pass[TEST_BOTH_SAMPLE_SEPARATE] = 1;
            }
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 7: Combined Trace & Profile Summary to Same File         */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[trace]\n"
            "file = %s\n"
            "seed = 1\n"
            "sink = 1\n"
            "thread = 1\n"
            "lazy-write = 0\n"
            "\n"
            "[profile]\n"
            "file = %s\n"
            "interval = %d\n"
            "each-sample = 0\n"
            "format-csv = 0\n",
            test_files[TEST_BOTH_SUMMARY_SHARED].trace_file,
            test_files[TEST_BOTH_SUMMARY_SHARED].profile_file,
            interval * 3);

        printf("Executing %s...\n", test_files[TEST_BOTH_SUMMARY_SHARED].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval * 3 + 2));
            if (validate_log_file(test_files[TEST_BOTH_SUMMARY_SHARED].trace_file, EXPECT_BOTH_SUMMARY))
                test_pass[TEST_BOTH_SUMMARY_SHARED] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 8: Combined Trace & Profile Summary to Separate Files    */
    /* ------------------------------------------------------------- */
    {
        char cfg[ARDENT_DEBUG_CONFIG_MAX];
        snprintf(cfg, sizeof(cfg),
            "[trace]\n"
            "file = %s\n"
            "seed = 1\n"
            "sink = 1\n"
            "thread = 1\n"
            "lazy-write = 0\n"
            "\n"
            "[profile]\n"
            "file = %s\n"
            "interval = %d\n"
            "each-sample = 0\n"
            "format-csv = 0\n",
            test_files[TEST_BOTH_SUMMARY_SEPARATE].trace_file,
            test_files[TEST_BOTH_SUMMARY_SEPARATE].profile_file,
            interval * 3);

        printf("Executing %s...\n", test_files[TEST_BOTH_SUMMARY_SEPARATE].test_name);
        if (send_reload_config(debug_ipc_path, cfg, strlen(cfg))) {
            sleep_seconds((unsigned int)(interval * 3 + 2));
            if (validate_log_file(test_files[TEST_BOTH_SUMMARY_SEPARATE].trace_file, EXPECT_TRACE_ONLY) &&
                validate_log_file(test_files[TEST_BOTH_SUMMARY_SEPARATE].profile_file, EXPECT_PROFILE_SUMMARY_ONLY)) {
                test_pass[TEST_BOTH_SUMMARY_SEPARATE] = 1;
            }
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 9: Invalid Configuration Rejection                       */
    /* ------------------------------------------------------------- */
    {
        /* Incomplete section (missing required 'file' or 'seed') */
        const char bad_cfg[] =
            "[trace]\n"
            "seed = 1\n"
            "thread = 1\n";

        printf("Executing %s...\n", test_files[TEST_INVALID_CONFIG].test_name);
        /* Expect send_reload_config to return 0 (rejection from provider) */
        if (!send_reload_config(debug_ipc_path, bad_cfg, strlen(bad_cfg)))
            test_pass[TEST_INVALID_CONFIG] = 1;
    }

    /* ------------------------------------------------------------- */
    /* Test 10: Runtime Debug Reset to Full Off (0-byte payload)      */
    /* ------------------------------------------------------------- */
    {
        printf("Executing %s...\n", test_files[TEST_DEBUG_RESET].test_name);
        if (send_reload_config(debug_ipc_path, "", 0)) {
            sleep_seconds((unsigned int)(interval + 1));
            test_pass[TEST_DEBUG_RESET] = 1;
        }
    }

    /* ------------------------------------------------------------- */
    /* Final Results Summary                                         */
    /* ------------------------------------------------------------- */
    {
        int all_passed = 1;
        int pass_count = 0;

        printf("\n============================================================\n");
        printf("              ARDENT Runtime Config Test Results\n");
        printf("============================================================\n");
        for (index = 0; index < TEST_COUNT; ++index) {
            if (test_pass[index]) {
                printf("  [PASS] %s\n", test_files[index].test_name);
                pass_count++;
            } else {
                printf("  [FAIL] %s\n", test_files[index].test_name);
                all_passed = 0;
            }
        }
        printf("============================================================\n");
        if (all_passed)
            printf("Overall Status: ALL TESTS PASSED (%d/%d)\n", pass_count, TEST_COUNT);
        else
            printf("Overall Status: SOME TESTS FAILED (%d/%d passed)\n", pass_count, TEST_COUNT);
        printf("============================================================\n");

        cleanup_test_files(preserve);
        return all_passed ? 0 : 1;
    }
}
