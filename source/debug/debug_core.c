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

#if defined(__linux__)
# define _GNU_SOURCE
#endif

#include "kpep/kpep.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "openssl/configuration.h"
#include "openssl/e_os2.h"

#if defined(OPENSSL_SYS_UNIX)
# include <errno.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/un.h>
# include <sys/stat.h>
# include <unistd.h>
# if defined(OPENSSL_SYS_SOLARIS)
#  include <ucred.h>
# endif
#elif defined(OPENSSL_SYS_WINDOWS)
# include <windows.h>
# include <sddl.h>
#endif

#include "internal/thread_arch.h"

#include "../kpep_internal.h"
#include "kpep/kpep_debug.h"
#include "debug_utility.h"
#include "debug_core.h"
#include "kpep/kpep_names.h"

#include "openssl/bio.h"
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/params.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

struct kpep_debug_sink_st {
	char *name;
	FILE *stream;
	int owned_stream;
	unsigned int refcount;
	CRYPTO_MUTEX *lock;
	struct kpep_debug_sink_st *next;
};

static int kpep_debug_apply_config(const char *buffer, size_t buffer_len);

/* ************************************************************************************************
 * ************************************************************************************************
 * LOCK/MUTEX management and operations
 * ************************************************************************************************
 * ***********************************************************************************************/

static CRYPTO_MUTEX *debug_core_mutex = NULL;
static CRYPTO_MUTEX *debug_reload_mutex = NULL;
static KPEP_DEBUG_SINK *debug_sinks = NULL;
static char debug_ipc_path[PATH_MAX] = {0};
static int debug_peer_security = 0;

#if defined(OPENSSL_SYS_UNIX)
static CRYPTO_THREAD *debug_listener_thread = NULL;
static int debug_listener_fd = -1;
static int debug_listener_stop = 0;
#elif defined(OPENSSL_SYS_WINDOWS)
static CRYPTO_THREAD *debug_listener_thread = NULL;
static CRYPTO_MUTEX *debug_listener_mutex = NULL;
static int debug_listener_stop = 0;
#endif

static void kpep_debug_core_lock(void)
{
	if (!debug_core_mutex)
		debug_core_mutex = ossl_crypto_mutex_new();
	if (debug_core_mutex)
		ossl_crypto_mutex_lock(debug_core_mutex);
}

static void kpep_debug_core_unlock(void)
{
	if (debug_core_mutex)
		ossl_crypto_mutex_unlock(debug_core_mutex);
}

static void kpep_debug_reload_lock(void)
{
	if (!debug_reload_mutex)
		debug_reload_mutex = ossl_crypto_mutex_new();
	if (debug_reload_mutex)
		ossl_crypto_mutex_lock(debug_reload_mutex);
}

static void kpep_debug_reload_unlock(void)
{
	if (debug_reload_mutex)
		ossl_crypto_mutex_unlock(debug_reload_mutex);
}

/* ************************************************************************************************
 * ************************************************************************************************
 * SINK management and operations
 * ************************************************************************************************
 * ***********************************************************************************************/

static 
KPEP_DEBUG_SINK *kpep_debug_find_sink(const char *name)
{
	KPEP_DEBUG_SINK *sink;

	for (sink = debug_sinks; sink; sink = sink->next) {
		if (strcmp(sink->name, name) == 0)
			return sink;
	}

	return NULL;
}

static 
void kpep_debug_destroy_sink(KPEP_DEBUG_SINK *sink)
{
	if (!sink)
		return;

	if (sink->stream) {
		if (sink->owned_stream)
			fclose(sink->stream);
		else
			fflush(sink->stream);
		sink->stream = NULL;
	}

	if (sink->lock)
		ossl_crypto_mutex_free(&sink->lock);

	OPENSSL_free(sink->name);
	OPENSSL_free(sink);
}

KPEP_DEBUG_SINK *kpep_debug_sink_acquire(const char *name,
										 const char *error_tag,
										 const char *env_name)
{
	KPEP_DEBUG_SINK *sink;
	FILE *stream = NULL;
	int owned_stream = 0;
	char errbuf[256] = {0};

	if (!name || name[0] == '\0')
		return NULL;

	kpep_debug_core_lock();
	sink = kpep_debug_find_sink(name);
	if (sink) {
		sink->refcount += 1;
		kpep_debug_core_unlock();
		return sink;
	}

	if (!kpep_debug_open_output(name,
								"KPEP Debug Output",
								&stream,
								&owned_stream,
								errbuf,
								sizeof(errbuf))) {
		kpep_debug_core_unlock();
		kpep_debug_report_error_once(error_tag,
									 "%s '%s' failed: %s",
									 env_name ? env_name : "debug output",
									 name,
									 errbuf[0] != '\0' ? errbuf : "unknown error");
		return NULL;
	}

	sink = OPENSSL_zalloc(sizeof(*sink));
	if (!sink) {
		if (owned_stream)
			fclose(stream);
		else
			fflush(stream);
		kpep_debug_core_unlock();
		kpep_debug_report_error_once(error_tag, "failed to allocate debug sink for %s", name);
		return NULL;
	}

	sink->name = OPENSSL_strdup(name);
	sink->lock = ossl_crypto_mutex_new();
	sink->stream = stream;
	sink->owned_stream = owned_stream;
	sink->refcount = 1;
	if (!sink->name || !sink->lock) {
		kpep_debug_destroy_sink(sink);
		kpep_debug_core_unlock();
		kpep_debug_report_error_once(error_tag, "failed to allocate debug sink for %s", name);
		return NULL;
	}

	sink->next = debug_sinks;
	debug_sinks = sink;
	kpep_debug_core_unlock();
	return sink;
}

void kpep_debug_sink_release(KPEP_DEBUG_SINK **sink_ptr)
{
	KPEP_DEBUG_SINK *sink;
	KPEP_DEBUG_SINK *iter;
	KPEP_DEBUG_SINK *prev = NULL;
	int free_mutex = 0;
	CRYPTO_MUTEX *mutex_to_free = NULL;

	if (!sink_ptr || !*sink_ptr)
		return;

	sink = *sink_ptr;
	*sink_ptr = NULL;

	kpep_debug_core_lock();
	if (sink->refcount > 1) {
		sink->refcount -= 1;
		kpep_debug_core_unlock();
		return;
	}

	for (iter = debug_sinks; iter; iter = iter->next) {
		if (iter == sink) {
			if (prev)
				prev->next = iter->next;
			else
				debug_sinks = iter->next;
			break;
		}
		prev = iter;
	}

	if (!debug_sinks && debug_core_mutex) {
		mutex_to_free = debug_core_mutex;
		debug_core_mutex = NULL;
		free_mutex = 1;
	}
	if (mutex_to_free)
		ossl_crypto_mutex_unlock(mutex_to_free);
	else
		kpep_debug_core_unlock();

	kpep_debug_destroy_sink(sink);
	if (free_mutex)
		ossl_crypto_mutex_free(&mutex_to_free);
}

int kpep_debug_sink_write(KPEP_DEBUG_SINK *sink, const char *text, int flush_output)
{
	int ok = 1;

	if (!sink || !sink->lock || !sink->stream || !text)
		return 0;

	ossl_crypto_mutex_lock(sink->lock);
	if (fputs(text, sink->stream) == EOF)
		ok = 0;

	if (ok && flush_output && fflush(sink->stream) != 0)
		ok = 0;

	if (!ok && ferror(sink->stream))
		clearerr(sink->stream);
	ossl_crypto_mutex_unlock(sink->lock);
	return ok;
}

/* ************************************************************************************************
* ************************************************************************************************
* SUBSYSTEM management and operations
* ************************************************************************************************
* ***********************************************************************************************/

// Forward declaration for the debug listener stop function
static void kpep_debug_listener_stop(void);

static void kpep_debug_cleanup_if_unused(void)
{
	CRYPTO_MUTEX *mutex_to_free = NULL;

	kpep_debug_core_lock();
	if (!debug_sinks && debug_core_mutex) {
		mutex_to_free = debug_core_mutex;
		debug_core_mutex = NULL;
	}
	if (mutex_to_free)
		ossl_crypto_mutex_unlock(mutex_to_free);
	else
		kpep_debug_core_unlock();

	if (mutex_to_free)
		ossl_crypto_mutex_free(&mutex_to_free);
}

void kpep_debug_fini(void)
{
	KPEP_DEBUG_SINK *sink;
	KPEP_DEBUG_SINK *next;
	CRYPTO_MUTEX *mutex_to_free = NULL;

#if defined(OPENSSL_SYS_UNIX) || defined(OPENSSL_SYS_WINDOWS)
	kpep_debug_listener_stop();
#endif
	kpep_debug_reload_lock();
	kpep_profile_fini();
	kpep_trace_fini();

	kpep_debug_core_lock();
	sink = debug_sinks;
	debug_sinks = NULL;
	if (debug_core_mutex) {
		mutex_to_free = debug_core_mutex;
		debug_core_mutex = NULL;
	}
	if (mutex_to_free)
		ossl_crypto_mutex_unlock(mutex_to_free);
	else
		kpep_debug_core_unlock();

	while (sink) {
		next = sink->next;
		kpep_debug_destroy_sink(sink);
		sink = next;
	}

	if (mutex_to_free)
		ossl_crypto_mutex_free(&mutex_to_free);

	kpep_debug_reload_unlock();
	if (debug_reload_mutex)
		ossl_crypto_mutex_free(&debug_reload_mutex);
	debug_ipc_path[0] = '\0';
	debug_peer_security = 0;
}

void kpep_debug_init(void)
{
	KPEP_DEBUG_TRACE_CONFIG trace_config = {0};
	KPEP_DEBUG_PROFILE_CONFIG profile_config = {0};
	const char *interval;

	trace_config.file = getenv(KPEP_ENV_TRACE_FILE);
	trace_config.seed = kpep_debug_is_enabled_flag(KPEP_ENV_TRACE_SEED);
	trace_config.sink = kpep_debug_is_enabled_flag(KPEP_ENV_TRACE_SINK);
	trace_config.thread = kpep_debug_is_enabled_flag(KPEP_ENV_TRACE_THREAD);
	trace_config.lazy_write = kpep_debug_is_enabled_flag(KPEP_ENV_TRACE_LAZY_WRITE);

	profile_config.file = getenv(KPEP_ENV_PROFILE_FILE);
	profile_config.each_sample = kpep_debug_is_enabled_flag(KPEP_ENV_PROFILE_EACH_SAMPLE);
	interval = getenv(KPEP_ENV_PROFILE_INTERVAL);
	if (interval && interval[0] != '\0' &&
		!kpep_debug_parse_interval(interval, &profile_config.interval)) {
		kpep_debug_report_error_once("PROFILE ERROR", "%s '%s' is invalid; profiling disabled",
			KPEP_ENV_PROFILE_INTERVAL, interval);
		profile_config.file = NULL;
		profile_config.each_sample = 0;
	}

	kpep_debug_reload_lock();
	kpep_profile_fini();
	kpep_trace_fini();
	kpep_trace_init(&trace_config);
	kpep_profile_init(&profile_config);
	kpep_debug_cleanup_if_unused();
	kpep_debug_reload_unlock();
}

static int kpep_debug_get_required_string(CONF *config,
		const char *section,
		const char *name,
		const char **out)
{
	const char *value = NCONF_get_string(config, section, name);

	if (!value || value[0] == '\0') {
		ERR_clear_error();
		return 0;
	}

	*out = value;
	return 1;
}

static int kpep_debug_apply_config(const char *buffer, size_t buffer_len)
{
	KPEP_DEBUG_TRACE_CONFIG trace_config = {0};
	KPEP_DEBUG_PROFILE_CONFIG profile_config = {0};
	int has_trace = 0;
	int has_profile = 0;
	BIO *bio = NULL;
	CONF *config = NULL;
	long error_line = 0;
	int result = 0;

	if (!buffer || buffer_len > KPEP_DEBUG_CONFIG_MAX)
		return 0;

	if (buffer_len > 0) {
		bio = BIO_new_mem_buf(buffer, (int)buffer_len);
		config = NCONF_new(NULL);
		if (!bio || !config)
			goto end;

		if (NCONF_load_bio(config, bio, &error_line) <= 0)
			goto end;

		if (NCONF_get_section(config, "trace") != NULL) {
			has_trace = 1;
			if (!kpep_debug_get_required_string(config, "trace", "file", &trace_config.file) ||
				!kpep_debug_parse_bool(NCONF_get_string(config, "trace", "seed"), &trace_config.seed) ||
				!kpep_debug_parse_bool(NCONF_get_string(config, "trace", "sink"), &trace_config.sink) ||
				!kpep_debug_parse_bool(NCONF_get_string(config, "trace", "thread"), &trace_config.thread) ||
				!kpep_debug_parse_bool(NCONF_get_string(config, "trace", "lazy-write"), &trace_config.lazy_write)) {
				goto end;
			}
		}

		if (NCONF_get_section(config, "profile") != NULL) {
			has_profile = 1;
			if (!kpep_debug_get_required_string(config, "profile", "file", &profile_config.file) ||
				!kpep_debug_parse_interval(NCONF_get_string(config, "profile", "interval"), &profile_config.interval) ||
				!kpep_debug_parse_bool(NCONF_get_string(config, "profile", "each-sample"), &profile_config.each_sample) ||
				!kpep_debug_parse_bool(NCONF_get_string(config, "profile", "format-csv"), &profile_config.format_csv)) {
				goto end;
			}
		}
	}

	kpep_debug_reload_lock();
	kpep_profile_fini();
	kpep_trace_fini();
	if (has_trace)
		kpep_trace_init(&trace_config);
	if (has_profile)
		kpep_profile_init(&profile_config);
	kpep_debug_cleanup_if_unused();
	kpep_debug_reload_unlock();
	result = 1;

end:
	ERR_clear_error();
	NCONF_free(config);
	BIO_free(bio);
	return result;
}

static int load_params(void *prov_ctx)
{
	const char *socket_value = NULL;
	const char *security_value = NULL;
	OSSL_PARAM params[3], *p = params;

	debug_ipc_path[0] = '\0';
	debug_peer_security = 0;

	if (!prov_ctx)
		return 0;

	*p++ = OSSL_PARAM_construct_utf8_ptr(KPEP_PROV_PARAM_DEBUG_IPC_PATH,
			(char **)&socket_value, sizeof(socket_value));
	*p++ = OSSL_PARAM_construct_utf8_ptr(KPEP_PROV_PARAM_DEBUG_SECURITY,
			(char **)&security_value, sizeof(security_value));
	*p = OSSL_PARAM_construct_end();

	if (!kpep_get_core_params(prov_ctx, params)) {
		kpep_debug_report_error_once("DEBUG ERROR", "failed to load debug control configuration");
		return 0;
	}

	if (!socket_value || socket_value[0] == '\0')
		return 1;

	if (strlen(socket_value) >= sizeof(debug_ipc_path)) {
		kpep_debug_report_error_once("DEBUG ERROR", "%s is too long", KPEP_PROV_PARAM_DEBUG_IPC_PATH);
		return 0;
	}

	if (security_value && security_value[0] != '\0') {
		if (strcmp(security_value, "peer") == 0)
			debug_peer_security = 1;
		else if (strcmp(security_value, "none") != 0) {
			kpep_debug_report_error_once("DEBUG ERROR", "%s must be 'none' or 'peer'", KPEP_PROV_PARAM_DEBUG_SECURITY);
			return 0;
		}
	}

	strcpy(debug_ipc_path, socket_value);
	return 1;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * IPC mechanism and peer config
 * ************************************************************************************************
 * ***********************************************************************************************/

#if defined(OPENSSL_SYS_UNIX)
static int kpep_debug_peer_allowed(int client_fd)
{
# if defined(OPENSSL_SYS_LINUX) && defined(SO_PEERCRED)
	struct ucred credentials;
	socklen_t credentials_len = sizeof(credentials);

	if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_len) != 0)
		return 0;

	return credentials.uid == 0;
# elif defined(OPENSSL_SYS_SOLARIS)
	ucred_t *credentials = NULL;

	if (getpeerucred(client_fd, &credentials) != 0)
		return 0;

	if (ucred_geteuid(credentials) != 0) {
		ucred_free(credentials);
		return 0;
	}

	ucred_free(credentials);
	return 1;
# elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	uid_t user_id;
	gid_t group_id;

	if (getpeereid(client_fd, &user_id, &group_id) != 0)
		return 0;

	return user_id == 0;
# else
	(void)client_fd;
	return 0;
# endif
}

static int kpep_debug_handle_client(int client_fd)
{
	char config[KPEP_DEBUG_CONFIG_MAX + 1];
	size_t config_len = 0;
	char acknowledge;
	ssize_t received;
	int result = 0;

	for (;;) {
		received = recv(client_fd, config + config_len,
			sizeof(config) - config_len, 0);
		if (received == 0)
			break;
		if (received < 0) {
			if (errno == EINTR)
				continue;
			goto end;
		}
		config_len += (size_t)received;
		if (config_len > KPEP_DEBUG_CONFIG_MAX)
			goto end;
	}

	result = kpep_debug_apply_config(config, config_len);

end:
	acknowledge = result ? KPEP_DEBUG_ACK_SUCCESS : KPEP_DEBUG_ACK_FAILURE;
	(void)send(client_fd, &acknowledge, sizeof(acknowledge), 0);
	return result;
}

static void kpep_debug_reject_client(int client_fd)
{
	char acknowledge = KPEP_DEBUG_ACK_FAILURE;

	(void)send(client_fd, &acknowledge, sizeof(acknowledge), 0);
}

static CRYPTO_THREAD_RETVAL kpep_debug_listener_main(void *unused)
{
	int listener_fd;

	(void)unused;
	kpep_debug_core_lock();
	listener_fd = debug_listener_fd;
	kpep_debug_core_unlock();

	while (listener_fd >= 0) {
		int client_fd = accept(listener_fd, NULL, NULL);

		if (client_fd < 0) {
			kpep_debug_core_lock();
			if (debug_listener_stop) {
				kpep_debug_core_unlock();
				break;
			}
			kpep_debug_core_unlock();
			if (errno == EINTR)
				continue;
			break;
		}

		if (!debug_peer_security || kpep_debug_peer_allowed(client_fd))
			kpep_debug_handle_client(client_fd);
		else {
			kpep_debug_report_error_once("DEBUG ERROR", "debug reload rejected: unauthorized peer");
			kpep_debug_reject_client(client_fd);
		}
		close(client_fd);
	}

	return 0;
}

static void kpep_debug_listener_stop(void)
{
	CRYPTO_THREAD *thread;
	CRYPTO_THREAD_RETVAL retval;
	int listener_fd;

	kpep_debug_core_lock();
	thread = debug_listener_thread;
	listener_fd = debug_listener_fd;
	debug_listener_thread = NULL;
	debug_listener_fd = -1;
	debug_listener_stop = 1;
	kpep_debug_core_unlock();

	if (listener_fd >= 0) {
		shutdown(listener_fd, SHUT_RDWR);
		close(listener_fd);
	}

	if (thread) {
		ossl_crypto_thread_native_join(thread, &retval);
		ossl_crypto_thread_native_clean(thread);
	}

	if (debug_ipc_path[0] != '\0') {
		unlink(debug_ipc_path);
		debug_ipc_path[0] = '\0';
	}
}

static void kpep_debug_atexit_cleanup(void)
{
	if (debug_ipc_path[0] != '\0')
		unlink(debug_ipc_path);
}

static int kpep_debug_prepare_socket_path(const char *path)
{
	struct sockaddr_un probe_addr;
	int probe_fd;

	if (!path || path[0] == '\0')
		return 0;

	/* Check if the socket file already exists on the filesystem */
	if (access(path, F_OK) != 0)
		return 1;

	/* Probe whether a live listener is actively accepting connections */
	probe_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (probe_fd < 0)
		return 1;

	memset(&probe_addr, 0, sizeof(probe_addr));
	probe_addr.sun_family = AF_UNIX;
	strncpy(probe_addr.sun_path, path, sizeof(probe_addr.sun_path) - 1);

	if (connect(probe_fd, (struct sockaddr *)&probe_addr, sizeof(probe_addr)) == 0) {
		/* An active listener is genuinely using this socket */
		close(probe_fd);
		kpep_debug_report_error_once("DEBUG ERROR",
			"debug socket '%s' is already in use by an active process", path);
		return 0;
	}

	close(probe_fd);

	/* Stale/orphaned socket file from a crashed or abruptly terminated run */
	unlink(path);
	return 1;
}

static int kpep_debug_listener_start(void)
{
	static int atexit_registered = 0;
	struct sockaddr_un address;
	mode_t old_umask;
	int listener_fd;

	if (debug_ipc_path[0] == '\0')
		return 1;

	if (strlen(debug_ipc_path) >= sizeof(address.sun_path)) {
		kpep_debug_report_error_once("DEBUG ERROR", "%s is too long", KPEP_PROV_PARAM_DEBUG_IPC_PATH);
		return 0;
	}

	if (!kpep_debug_prepare_socket_path(debug_ipc_path))
		return 0;

	if (!atexit_registered) {
		atexit(kpep_debug_atexit_cleanup);
		atexit_registered = 1;
	}

	listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener_fd < 0) {
		kpep_debug_report_error_once("DEBUG ERROR", "failed to create debug control socket: %s", strerror(errno));
		return 0;
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, debug_ipc_path);
	old_umask = umask(debug_peer_security ? 0077 : 0000);
	if (bind(listener_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		umask(old_umask);
		kpep_debug_report_error_once("DEBUG ERROR", "failed to bind debug socket '%s': %s",
			debug_ipc_path, strerror(errno));
		close(listener_fd);
		return 0;
	}
	umask(old_umask);

	if (listen(listener_fd, 4) != 0) {
		kpep_debug_report_error_once("DEBUG ERROR", "failed to listen on debug socket '%s': %s",
			debug_ipc_path, strerror(errno));
		close(listener_fd);
		unlink(debug_ipc_path);
		return 0;
	}

	kpep_debug_core_lock();
	debug_listener_stop = 0;
	debug_listener_fd = listener_fd;
	debug_listener_thread = ossl_crypto_thread_native_start(kpep_debug_listener_main, NULL, 1);
	if (!debug_listener_thread) {
		debug_listener_fd = -1;
		kpep_debug_core_unlock();
		kpep_debug_report_error_once("DEBUG ERROR", "failed to start debug control listener");
		close(listener_fd);
		unlink(debug_ipc_path);
		return 0;
	}
	kpep_debug_core_unlock();
	return 1;
}
#endif

#if defined(OPENSSL_SYS_WINDOWS)
static void kpep_debug_listener_lock(void)
{
	if (!debug_listener_mutex)
		debug_listener_mutex = ossl_crypto_mutex_new();
	if (debug_listener_mutex)
		ossl_crypto_mutex_lock(debug_listener_mutex);
}

static void kpep_debug_listener_unlock(void)
{
	if (debug_listener_mutex)
		ossl_crypto_mutex_unlock(debug_listener_mutex);
}

static int kpep_debug_peer_allowed(HANDLE pipe)
{
	HANDLE token = NULL;
	PSID administrators_sid = NULL;
	SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
	BOOL is_administrator = FALSE;
	int allowed = 0;

	if (!ImpersonateNamedPipeClient(pipe))
		return 0;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
		goto end;

	if (!AllocateAndInitializeSid(&authority,
			2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0,
			&administrators_sid))
		goto end;

	if (CheckTokenMembership(token, administrators_sid, &is_administrator) && is_administrator)
		allowed = 1;

end:
	if (administrators_sid)
		FreeSid(administrators_sid);
	if (token)
		CloseHandle(token);
	RevertToSelf();
	return allowed;
}

static int kpep_debug_handle_client(HANDLE pipe)
{
	char config[KPEP_DEBUG_CONFIG_MAX + 1];
	DWORD received = 0;
	DWORD written = 0;
	char acknowledge;
	int result = 0;

	if (ReadFile(pipe, config, sizeof(config), &received, NULL) &&
		received <= KPEP_DEBUG_CONFIG_MAX)
		result = kpep_debug_apply_config(config, (size_t)received);

	acknowledge = result ? KPEP_DEBUG_ACK_SUCCESS : KPEP_DEBUG_ACK_FAILURE;
	(void)WriteFile(pipe, &acknowledge, sizeof(acknowledge), &written, NULL);
	return result;
}

static CRYPTO_THREAD_RETVAL kpep_debug_listener_main(void *unused)
{
	(void)unused;

	for (;;) {
		HANDLE pipe;
		BOOL connected;
		DWORD error;
		int stop_requested;

		pipe = CreateNamedPipeA(debug_ipc_path,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			1,
			0,
			0,
			0,
			NULL);
		if (pipe == INVALID_HANDLE_VALUE)
			break;

		connected = ConnectNamedPipe(pipe, NULL);
		error = connected ? ERROR_SUCCESS : GetLastError();
		if (!connected && error != ERROR_PIPE_CONNECTED) {
			CloseHandle(pipe);
			break;
		}

		kpep_debug_listener_lock();
		stop_requested = debug_listener_stop;
		kpep_debug_listener_unlock();
		if (!stop_requested) {
			if (!debug_peer_security || kpep_debug_peer_allowed(pipe))
				kpep_debug_handle_client(pipe);
			else
				kpep_debug_report_error_once("DEBUG ERROR", "debug reload rejected: unauthorized peer");
		}

		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
		if (stop_requested)
			break;
	}

	return 0;
}

static void kpep_debug_listener_stop(void)
{
	CRYPTO_THREAD *thread;
	CRYPTO_THREAD_RETVAL retval;
	HANDLE pipe;

	kpep_debug_listener_lock();
	thread = debug_listener_thread;
	debug_listener_thread = NULL;
	debug_listener_stop = 1;
	kpep_debug_listener_unlock();

	if (thread) {
		pipe = CreateFileA(debug_ipc_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipe != INVALID_HANDLE_VALUE)
			CloseHandle(pipe);
		ossl_crypto_thread_native_join(thread, &retval);
		ossl_crypto_thread_native_clean(thread);
	}

	if (debug_listener_mutex)
		ossl_crypto_mutex_free(&debug_listener_mutex);
}

static int kpep_debug_listener_start(void)
{
	if (debug_ipc_path[0] == '\0')
		return 1;

	kpep_debug_listener_lock();
	debug_listener_stop = 0;
	debug_listener_thread = ossl_crypto_thread_native_start(kpep_debug_listener_main, NULL, 1);
	if (!debug_listener_thread) {
		kpep_debug_listener_unlock();
		kpep_debug_report_error_once("DEBUG ERROR", "failed to start debug control listener");
		return 0;
	}
	kpep_debug_listener_unlock();
	return 1;
}
#endif

void kpep_debug_control_init(void *prov_ctx)
{
	if (!load_params(prov_ctx))
		return;

#if defined(OPENSSL_SYS_UNIX) || defined(OPENSSL_SYS_WINDOWS)
	kpep_debug_listener_start();
#else
	if (debug_ipc_path[0] != '\0')
		kpep_debug_report_error_once("DEBUG ERROR", "debug control listener is unsupported on this platform");
#endif
}
