#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd_buf.h"
#include "jobd_config.h"

#ifndef JOBD_PREFIX
#define JOBD_PREFIX "/usr/local"
#endif

#ifndef JOBD_SYSCONFDIR
#define JOBD_SYSCONFDIR "/etc"
#endif

#define MAX_SEARCH_DIRS 24

struct component_def {
	const char *name;
	const char *env;
};

static const struct component_def comp_defs[JOBD_COMP__COUNT] = {
	[JOBD_COMP_CGROUPD]         = { "cgroupd",       "JOBD_CGROUPD"         },
	[JOBD_COMP_CGROUPCTL]       = { "cgroupctl",     "JOBD_CGROUPCTL"       },
	[JOBD_COMP_OVERLAYD]        = { "overlayd",      "JOBD_OVERLAYD"        },
	[JOBD_COMP_SANDBOX]         = { "sandbox",       "JOBD_SANDBOX"         },
	[JOBD_COMP_LANDLOCKD]       = { "landlockd",     "JOBD_LANDLOCKD"       },
	[JOBD_COMP_FANOTIFYD]       = { "fanotifyd",     "JOBD_FANOTIFYD"       },
	[JOBD_COMP_MEMFDBUS]        = { "memfdbus",      "JOBD_MEMFDBUS"        },
	[JOBD_COMP_IOURINGD]        = { "iouringd",      "JOBD_IOURINGD"        },
	[JOBD_COMP_JOB_INIT]        = { "job-init",      "JOBD_JOB_INIT"        },
	[JOBD_COMP_JOB_NETD]        = { "job-netd",      "JOBD_JOB_NETD"        },
	[JOBD_COMP_LANDLOCK_HELPER] = { "landlockd-policy-helper",
	                                  "JOBD_LANDLOCKD_POLICY_HELPER"          },
};

static struct jobd_paths  g_paths;
static struct jobd_access g_access;
static struct jobd_features g_features;

static char g_override[JOBD_COMP__COUNT][JOBD_PATH_MAX];
static char g_resolved[JOBD_COMP__COUNT][JOBD_PATH_MAX];
static int  g_resolve_done[JOBD_COMP__COUNT];

static char g_search_dirs[MAX_SEARCH_DIRS][JOBD_PATH_MAX];
static int  g_search_count;
static int  g_initialised;

static void copy_str(char *dst, size_t dst_sz, const char *src)
{
	if (dst_sz == 0)
		return;
	size_t len = strlen(src);
	if (len >= dst_sz)
		len = dst_sz - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

static void add_search_dir(const char *dir)
{
	if (!dir || !*dir || g_search_count >= MAX_SEARCH_DIRS)
		return;
	for (int i = 0; i < g_search_count; i++) {
		if (strcmp(g_search_dirs[i], dir) == 0)
			return;
	}
	copy_str(g_search_dirs[g_search_count], JOBD_PATH_MAX, dir);
	g_search_count++;
}

static void add_search_list(const char *list)
{
	if (!list)
		return;
	char tmp[JOBD_PATH_MAX * 4];
	copy_str(tmp, sizeof(tmp), list);

	char *save = NULL;
	for (char *tok = strtok_r(tmp, ":", &save); tok;
	     tok = strtok_r(NULL, ":", &save))
		add_search_dir(tok);
}

static void add_exe_dir(void)
{
	char exe[JOBD_PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0)
		return;
	exe[n] = '\0';

	char *slash = strrchr(exe, '/');
	if (!slash || slash == exe)
		return;
	*slash = '\0';
	add_search_dir(exe);
}

static void init_defaults(void)
{
	memset(&g_paths, 0, sizeof(g_paths));
	memset(&g_access, 0, sizeof(g_access));

	copy_str(g_paths.runtime_dir, JOBD_PATH_MAX, "/run/jobd");
	copy_str(g_paths.state_dir,   JOBD_PATH_MAX, "/var/lib/jobd");
	copy_str(g_paths.socket_path, sizeof(g_paths.socket_path),
	         "/run/jobd/jobd.sock");
	copy_str(g_paths.cgroup_sock, JOBD_PATH_MAX, "/run/jobd/cgroupd.sock");
	copy_str(g_paths.cgroup_root, JOBD_PATH_MAX,
	         "/sys/fs/cgroup/jobd.slice");
	copy_str(g_paths.cgroup_log_dir, JOBD_PATH_MAX, "/run/jobd/cgroup-logs");
	copy_str(g_paths.config_file, JOBD_PATH_MAX,
	         JOBD_SYSCONFDIR "/jobd/jobd.conf");

	g_access.allow_uid[0]    = 0;
	g_access.allow_uid_count = 1;
	g_access.allow_gid_count = 0;

	g_features.allow_iouring  = 1;
	g_features.allow_network  = 1;
	g_features.allow_fanotify = 1;
	g_features.allow_memfd    = 1;
}

static void join(char *dst, size_t dst_sz, const char *base, const char *leaf)
{
	int n = snprintf(dst, dst_sz, "%s/%s", base, leaf);
	if (n < 0 || (size_t)n >= dst_sz) {

		copy_str(dst, dst_sz, base);
	}
}

static void refresh_derived(void)
{
	join(g_paths.jobs_dir, JOBD_PATH_MAX, g_paths.state_dir, "jobs");
	join(g_paths.overlay_dir, JOBD_PATH_MAX, g_paths.state_dir, "overlay");
}

static void init_search_path(void)
{
	g_search_count = 0;

	const char *custom = getenv("JOBD_COMPONENT_PATH");
	if (custom && *custom) {
		add_search_list(custom);
		return;
	}

	add_exe_dir();
	add_search_dir(JOBD_PREFIX "/libexec/jobd");
	add_search_dir(JOBD_PREFIX "/bin");
	add_search_dir(JOBD_PREFIX "/sbin");
	add_search_dir("/usr/local/bin");
	add_search_dir("/usr/local/sbin");
	add_search_dir("/usr/bin");
	add_search_dir("/usr/sbin");
	add_search_dir("/bin");
	add_search_dir("/sbin");
}

void jobd_config_init(void)
{
	init_defaults();
	memset(g_override, 0, sizeof(g_override));
	memset(g_resolved, 0, sizeof(g_resolved));
	memset(g_resolve_done, 0, sizeof(g_resolve_done));

	for (int i = 0; i < JOBD_COMP__COUNT; i++) {
		if (!comp_defs[i].env)
			continue;
		const char *v = getenv(comp_defs[i].env);
		if (v && *v)
			copy_str(g_override[i], JOBD_PATH_MAX, v);
	}

	const char *v;
	if ((v = getenv("JOBD_RUNTIME_DIR")) && *v)
		copy_str(g_paths.runtime_dir, JOBD_PATH_MAX, v);
	if ((v = getenv("JOBD_STATE_DIR")) && *v)
		copy_str(g_paths.state_dir, JOBD_PATH_MAX, v);
	if ((v = getenv("JOBD_SOCKET")) && *v)
		copy_str(g_paths.socket_path, sizeof(g_paths.socket_path), v);
	if ((v = getenv("JOBD_CGROUP_SOCK")) && *v)
		copy_str(g_paths.cgroup_sock, JOBD_PATH_MAX, v);
	if ((v = getenv("JOBD_CGROUP_ROOT")) && *v)
		copy_str(g_paths.cgroup_root, JOBD_PATH_MAX, v);
	if ((v = getenv("JOBD_CGROUP_LOG_DIR")) && *v)
		copy_str(g_paths.cgroup_log_dir, JOBD_PATH_MAX, v);
	if ((v = getenv("JOBD_CONFIG")) && *v)
		copy_str(g_paths.config_file, JOBD_PATH_MAX, v);

	refresh_derived();
	init_search_path();
	g_initialised = 1;
}

static int comp_by_name(const char *name)
{
	for (int i = 0; i < JOBD_COMP__COUNT; i++) {
		if (comp_defs[i].name && strcmp(comp_defs[i].name, name) == 0)
			return i;
	}
	return -1;
}

static int parse_id_list(const char *value, unsigned *out, int max, int *count)
{
	char tmp[256];
	copy_str(tmp, sizeof(tmp), value);
	*count = 0;

	char *save = NULL;
	for (char *tok = strtok_r(tmp, ",", &save); tok && *count < max;
	     tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ')
			tok++;
		char *end = NULL;
		errno = 0;
		unsigned long id = strtoul(tok, &end, 10);
		if (errno != 0 || end == tok || id > 0xFFFFFFFFUL)
			return -1;
		out[(*count)++] = (unsigned)id;
	}
	return 0;
}

static int parse_bool(const char *value, int *out)
{
	static const char *yes[] = { "1", "yes", "true", "on", NULL };
	static const char *no[]  = { "0", "no", "false", "off", NULL };

	while (*value == ' ' || *value == '\t')
		value++;

	for (int i = 0; yes[i]; i++) {
		if (strcasecmp(value, yes[i]) == 0) {
			*out = 1;
			return 0;
		}
	}
	for (int i = 0; no[i]; i++) {
		if (strcasecmp(value, no[i]) == 0) {
			*out = 0;
			return 0;
		}
	}
	return -1;
}

static int set_feature(const char *key, const char *value, int *slot,
                       char *err, size_t err_sz)
{
	if (parse_bool(value, slot) != 0) {
		snprintf(err, err_sz,
		         "%s: expected yes or no (got '%s')", key, value);
		return -1;
	}
	return 0;
}

int jobd_config_set(const char *key, const char *value,
                      char *err, size_t err_sz)
{
	if (!g_initialised)
		jobd_config_init();

	if (!key || !value) {
		snprintf(err, err_sz, "missing key or value");
		return -1;
	}

	int c = comp_by_name(key);
	if (c >= 0) {
		if (value[0] != '/') {
			snprintf(err, err_sz,
			         "%s: component path must be absolute", key);
			return -1;
		}
		copy_str(g_override[c], JOBD_PATH_MAX, value);
		g_resolve_done[c] = 0;
		return 0;
	}

	if (strcmp(key, "runtime_dir") == 0) {
		copy_str(g_paths.runtime_dir, JOBD_PATH_MAX, value);
		return 0;
	}
	if (strcmp(key, "state_dir") == 0) {
		copy_str(g_paths.state_dir, JOBD_PATH_MAX, value);
		refresh_derived();
		return 0;
	}
	if (strcmp(key, "socket") == 0) {
		if (strlen(value) >= sizeof(g_paths.socket_path)) {
			snprintf(err, err_sz, "socket path too long (max %zu)",
			         sizeof(g_paths.socket_path) - 1);
			return -1;
		}
		copy_str(g_paths.socket_path, sizeof(g_paths.socket_path), value);
		return 0;
	}
	if (strcmp(key, "cgroup_sock") == 0) {
		copy_str(g_paths.cgroup_sock, JOBD_PATH_MAX, value);
		return 0;
	}
	if (strcmp(key, "cgroup_root") == 0) {
		copy_str(g_paths.cgroup_root, JOBD_PATH_MAX, value);
		return 0;
	}
	if (strcmp(key, "cgroup_log_dir") == 0) {
		copy_str(g_paths.cgroup_log_dir, JOBD_PATH_MAX, value);
		return 0;
	}
	if (strcmp(key, "component_path") == 0) {
		g_search_count = 0;
		add_search_list(value);
		memset(g_resolve_done, 0, sizeof(g_resolve_done));
		return 0;
	}
	if (strcmp(key, "allow_uid") == 0) {
		unsigned ids[16];
		int n = 0;
		if (parse_id_list(value, ids, 16, &n) != 0) {
			snprintf(err, err_sz, "allow_uid: invalid list");
			return -1;
		}
		for (int i = 0; i < n; i++)
			g_access.allow_uid[i] = (uid_t)ids[i];
		g_access.allow_uid_count = n;
		return 0;
	}
	if (strcmp(key, "allow_gid") == 0) {
		unsigned ids[16];
		int n = 0;
		if (parse_id_list(value, ids, 16, &n) != 0) {
			snprintf(err, err_sz, "allow_gid: invalid list");
			return -1;
		}
		for (int i = 0; i < n; i++)
			g_access.allow_gid[i] = (gid_t)ids[i];
		g_access.allow_gid_count = n;
		return 0;
	}

	if (strcmp(key, "allow_iouring") == 0)
		return set_feature(key, value, &g_features.allow_iouring,
		                   err, err_sz);
	if (strcmp(key, "allow_network") == 0)
		return set_feature(key, value, &g_features.allow_network,
		                   err, err_sz);
	if (strcmp(key, "allow_fanotify") == 0)
		return set_feature(key, value, &g_features.allow_fanotify,
		                   err, err_sz);
	if (strcmp(key, "allow_memfd") == 0)
		return set_feature(key, value, &g_features.allow_memfd,
		                   err, err_sz);

	snprintf(err, err_sz, "unknown configuration key: %s", key);
	return -1;
}

int jobd_config_load_file(const char *path, char *err, size_t err_sz)
{
	if (!g_initialised)
		jobd_config_init();

	const char *file = path ? path : g_paths.config_file;
	if (path)
		copy_str(g_paths.config_file, JOBD_PATH_MAX, path);

	FILE *f = fopen(file, "re");
	if (!f) {
		if (errno == ENOENT)
			return 0;
		snprintf(err, err_sz, "cannot read %s: %s", file, strerror(errno));
		return -1;
	}

	char line[1024];
	int lineno = 0;
	int rc = 0;

	while (fgets(line, sizeof(line), f)) {
		lineno++;

		char *s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '#' || *s == ';' || *s == '\n' || *s == '\0')
			continue;

		char *nl = strpbrk(s, "\r\n");
		if (nl)
			*nl = '\0';

		char *eq = strchr(s, '=');
		if (!eq) {
			snprintf(err, err_sz, "%s:%d: expected key = value",
			         file, lineno);
			rc = -1;
			break;
		}
		*eq = '\0';

		char *k = s;
		char *end = k + strlen(k);
		while (end > k && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';

		char *v = eq + 1;
		while (*v == ' ' || *v == '\t')
			v++;
		end = v + strlen(v);
		while (end > v && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';

		char serr[256];
		if (jobd_config_set(k, v, serr, sizeof(serr)) != 0) {
			snprintf(err, err_sz, "%s:%d: %s", file, lineno, serr);
			rc = -1;
			break;
		}
	}

	fclose(f);
	return rc;
}

const struct jobd_paths *jobd_paths(void)
{
	if (!g_initialised)
		jobd_config_init();
	return &g_paths;
}

const struct jobd_features *jobd_features(void)
{
	if (!g_initialised)
		jobd_config_init();
	return &g_features;
}

const struct jobd_access *jobd_access(void)
{
	if (!g_initialised)
		jobd_config_init();
	return &g_access;
}

const char *jobd_component_name(enum jobd_component c)
{
	if (c < 0 || c >= JOBD_COMP__COUNT)
		return "?";
	return comp_defs[c].name;
}

static int is_executable_file(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return 0;
	if (!S_ISREG(st.st_mode))
		return 0;
	return access(path, X_OK) == 0;
}

const char *jobd_component_path(enum jobd_component c)
{
	if (c < 0 || c >= JOBD_COMP__COUNT)
		return NULL;
	if (!g_initialised)
		jobd_config_init();

	if (g_resolve_done[c])
		return g_resolved[c][0] ? g_resolved[c] : NULL;

	g_resolve_done[c] = 1;
	g_resolved[c][0]  = '\0';

	if (g_override[c][0]) {
		copy_str(g_resolved[c], JOBD_PATH_MAX, g_override[c]);
		return g_resolved[c];
	}

	for (int i = 0; i < g_search_count; i++) {
		char cand[JOBD_PATH_MAX];
		int n = snprintf(cand, sizeof(cand), "%s/%s",
		                 g_search_dirs[i], comp_defs[c].name);
		if (n < 0 || (size_t)n >= sizeof(cand))
			continue;
		if (is_executable_file(cand)) {
			copy_str(g_resolved[c], JOBD_PATH_MAX, cand);
			return g_resolved[c];
		}
	}

	return NULL;
}

void jobd_component_search_desc(char *out, size_t out_sz)
{
	struct agd_buf b;
	agd_buf_init(&b, out, out_sz);

	if (!g_initialised)
		jobd_config_init();

	for (int i = 0; i < g_search_count; i++) {
		if (i > 0)
			agd_buf_adds(&b, ":");
		agd_buf_adds(&b, g_search_dirs[i]);
	}
}

int jobd_job_dir(const char *job_id, char *out, size_t out_sz)
{
	int n = snprintf(out, out_sz, "%s/%s", jobd_paths()->runtime_dir, job_id);
	return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
}

int jobd_job_subdir(const char *job_id, const char *sub,
                      char *out, size_t out_sz)
{
	int n = snprintf(out, out_sz, "%s/%s/%s",
	                 jobd_paths()->runtime_dir, job_id, sub);
	return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
}

int jobd_job_state_dir(const char *job_id, char *out, size_t out_sz)
{
	int n = snprintf(out, out_sz, "%s/%s", jobd_paths()->jobs_dir, job_id);
	return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
}
