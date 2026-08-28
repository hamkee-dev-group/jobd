#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd.h"

#define MAX_PHDR      128
#define MAX_DYN       4096
#define MAX_LIB_DIRS  64
#define MAX_SONAME    256

struct load_seg {
	uint64_t vaddr;
	uint64_t offset;
	uint64_t filesz;
};

struct elf_info {
	int             is64;
	struct load_seg loads[MAX_PHDR];
	int             load_count;
	uint64_t        dyn_off;
	uint64_t        dyn_size;
	uint64_t        interp_off;
	uint64_t        interp_size;
	int             has_dyn;
};

static char g_lib_dirs[MAX_LIB_DIRS][JOBD_PATH_LEN_LONG];
static int  g_lib_dir_count;
static int  g_lib_dirs_ready;

static void lib_dir_add(const char *dir)
{
	if (!dir || !*dir || g_lib_dir_count >= MAX_LIB_DIRS)
		return;
	for (int i = 0; i < g_lib_dir_count; i++) {
		if (strcmp(g_lib_dirs[i], dir) == 0)
			return;
	}
	snprintf(g_lib_dirs[g_lib_dir_count], JOBD_PATH_LEN_LONG, "%s", dir);
	g_lib_dir_count++;
}

static void lib_dirs_from_conf(const char *path, int depth);

static void lib_dirs_include(const char *pattern, int depth)
{
	glob_t g;
	memset(&g, 0, sizeof(g));
	if (glob(pattern, 0, NULL, &g) == 0) {
		for (size_t i = 0; i < g.gl_pathc; i++)
			lib_dirs_from_conf(g.gl_pathv[i], depth + 1);
	}
	globfree(&g);
}

static void lib_dirs_from_conf(const char *path, int depth)
{
	if (depth > 4)
		return;

	FILE *f = fopen(path, "re");
	if (!f)
		return;

	char line[1024];
	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		char *nl = strpbrk(s, "\r\n#");
		if (nl)
			*nl = '\0';
		char *end = s + strlen(s);
		while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (*s == '\0')
			continue;

		if (strncmp(s, "include", 7) == 0 &&
		    (s[7] == ' ' || s[7] == '\t')) {
			char *pat = s + 8;
			while (*pat == ' ' || *pat == '\t')
				pat++;
			if (*pat)
				lib_dirs_include(pat, depth);
			continue;
		}

		if (*s == '/')
			lib_dir_add(s);
	}

	fclose(f);
}

static void lib_dirs_init(void)
{
	if (g_lib_dirs_ready)
		return;
	g_lib_dirs_ready = 1;

	lib_dirs_from_conf("/etc/ld.so.conf", 0);

	lib_dir_add("/lib64");
	lib_dir_add("/usr/lib64");
	lib_dir_add("/lib");
	lib_dir_add("/usr/lib");
	lib_dir_add("/usr/local/lib");
}

static int read_at(int fd, void *buf, size_t n, uint64_t off)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = pread(fd, (char *)buf + got, n - got,
		                  (off_t)(off + got));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;
		got += (size_t)r;
	}
	return 0;
}

static int host_endian_ok(unsigned char ei_data)
{
	const uint16_t probe = 1;
	int little = *(const unsigned char *)&probe == 1;
	return little ? (ei_data == ELFDATA2LSB) : (ei_data == ELFDATA2MSB);
}

static int parse_headers(int fd, struct elf_info *info, char *err, size_t err_sz)
{
	unsigned char ident[EI_NIDENT];
	if (read_at(fd, ident, sizeof(ident), 0) != 0) {
		snprintf(err, err_sz, "cannot read ELF identification");
		return -1;
	}
	if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
		snprintf(err, err_sz, "not an ELF file");
		return -1;
	}
	if (ident[EI_CLASS] != ELFCLASS32 && ident[EI_CLASS] != ELFCLASS64) {
		snprintf(err, err_sz, "unsupported ELF class");
		return -1;
	}
	if (!host_endian_ok(ident[EI_DATA])) {
		snprintf(err, err_sz,
		         "ELF byte order differs from the host; cannot resolve "
		         "dependencies");
		return -1;
	}

	memset(info, 0, sizeof(*info));
	info->is64 = (ident[EI_CLASS] == ELFCLASS64);

	uint64_t phoff;
	uint16_t phnum, phentsize;

	if (info->is64) {
		Elf64_Ehdr eh;
		if (read_at(fd, &eh, sizeof(eh), 0) != 0) {
			snprintf(err, err_sz, "cannot read ELF header");
			return -1;
		}
		phoff     = eh.e_phoff;
		phnum     = eh.e_phnum;
		phentsize = eh.e_phentsize;
		if (phentsize < sizeof(Elf64_Phdr)) {
			snprintf(err, err_sz, "bad program header size");
			return -1;
		}
	} else {
		Elf32_Ehdr eh;
		if (read_at(fd, &eh, sizeof(eh), 0) != 0) {
			snprintf(err, err_sz, "cannot read ELF header");
			return -1;
		}
		phoff     = eh.e_phoff;
		phnum     = eh.e_phnum;
		phentsize = eh.e_phentsize;
		if (phentsize < sizeof(Elf32_Phdr)) {
			snprintf(err, err_sz, "bad program header size");
			return -1;
		}
	}

	if (phnum == 0 || phnum > MAX_PHDR) {
		snprintf(err, err_sz, "unsupported program header count (%u)", phnum);
		return -1;
	}

	for (uint16_t i = 0; i < phnum; i++) {
		uint64_t off = phoff + (uint64_t)i * phentsize;
		uint32_t type;
		uint64_t p_off, p_vaddr, p_filesz;

		if (info->is64) {
			Elf64_Phdr ph;
			if (read_at(fd, &ph, sizeof(ph), off) != 0)
				break;
			type = ph.p_type; p_off = ph.p_offset;
			p_vaddr = ph.p_vaddr; p_filesz = ph.p_filesz;
		} else {
			Elf32_Phdr ph;
			if (read_at(fd, &ph, sizeof(ph), off) != 0)
				break;
			type = ph.p_type; p_off = ph.p_offset;
			p_vaddr = ph.p_vaddr; p_filesz = ph.p_filesz;
		}

		switch (type) {
		case PT_LOAD:
			if (info->load_count < MAX_PHDR) {
				info->loads[info->load_count].vaddr  = p_vaddr;
				info->loads[info->load_count].offset = p_off;
				info->loads[info->load_count].filesz = p_filesz;
				info->load_count++;
			}
			break;
		case PT_DYNAMIC:
			info->dyn_off  = p_off;
			info->dyn_size = p_filesz;
			info->has_dyn  = 1;
			break;
		case PT_INTERP:
			info->interp_off  = p_off;
			info->interp_size = p_filesz;
			break;
		default:
			break;
		}
	}

	return 0;
}

static int vaddr_to_off(const struct elf_info *info, uint64_t vaddr,
                        uint64_t *out)
{
	for (int i = 0; i < info->load_count; i++) {
		const struct load_seg *l = &info->loads[i];
		if (vaddr >= l->vaddr && vaddr < l->vaddr + l->filesz) {
			*out = l->offset + (vaddr - l->vaddr);
			return 0;
		}
	}
	return -1;
}

static int read_string_at(int fd, uint64_t off, char *dst, size_t dst_sz)
{
	size_t n = 0;
	while (n < dst_sz - 1) {
		char c;
		ssize_t r = pread(fd, &c, 1, (off_t)(off + n));
		if (r <= 0)
			break;
		if (c == '\0')
			break;
		dst[n++] = c;
	}
	dst[n] = '\0';
	return n > 0 ? 0 : -1;
}

struct dyn_result {
	char needed[JOB_ELF_MAX_DEPS][MAX_SONAME];
	int  needed_count;
	char runpath[JOBD_PATH_LEN_LONG];
};

static int parse_dynamic(int fd, const struct elf_info *info,
                         struct dyn_result *out)
{
	memset(out, 0, sizeof(*out));
	if (!info->has_dyn)
		return 0;

	uint64_t strtab_vaddr = 0, strsz = 0;
	uint64_t needed_off[JOB_ELF_MAX_DEPS];
	int      needed_n = 0;
	uint64_t runpath_off = 0;
	int      have_runpath = 0;

	size_t entsize = info->is64 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
	uint64_t count = info->dyn_size / entsize;
	if (count > MAX_DYN)
		count = MAX_DYN;

	for (uint64_t i = 0; i < count; i++) {
		uint64_t off = info->dyn_off + i * entsize;
		int64_t  tag;
		uint64_t val;

		if (info->is64) {
			Elf64_Dyn d;
			if (read_at(fd, &d, sizeof(d), off) != 0)
				break;
			tag = (int64_t)d.d_tag;
			val = d.d_un.d_val;
		} else {
			Elf32_Dyn d;
			if (read_at(fd, &d, sizeof(d), off) != 0)
				break;
			tag = (int32_t)d.d_tag;
			val = d.d_un.d_val;
		}

		if (tag == DT_NULL)
			break;

		switch (tag) {
		case DT_STRTAB: strtab_vaddr = val; break;
		case DT_STRSZ:  strsz = val;        break;
		case DT_NEEDED:
			if (needed_n < JOB_ELF_MAX_DEPS)
				needed_off[needed_n++] = val;
			break;
		case DT_RUNPATH:
		case DT_RPATH:
			if (!have_runpath) {
				runpath_off  = val;
				have_runpath = 1;
			}
			break;
		default:
			break;
		}
	}

	if (strtab_vaddr == 0 || needed_n == 0)
		return 0;

	uint64_t strtab_off;
	if (vaddr_to_off(info, strtab_vaddr, &strtab_off) != 0)
		return 0;

	for (int i = 0; i < needed_n; i++) {
		if (strsz && needed_off[i] >= strsz)
			continue;
		char name[MAX_SONAME];
		if (read_string_at(fd, strtab_off + needed_off[i],
		                   name, sizeof(name)) != 0)
			continue;
		if (strchr(name, '/'))
			continue;
		snprintf(out->needed[out->needed_count], MAX_SONAME, "%s", name);
		out->needed_count++;
	}

	if (have_runpath && (!strsz || runpath_off < strsz))
		read_string_at(fd, strtab_off + runpath_off,
		               out->runpath, sizeof(out->runpath));

	return 0;
}

static int deps_contains(const struct job_elf_deps *d, const char *path)
{
	for (int i = 0; i < d->count; i++) {
		if (strcmp(d->paths[i], path) == 0)
			return 1;
	}
	return 0;
}

static int deps_add(struct job_elf_deps *d, const char *path)
{
	if (deps_contains(d, path))
		return 1;
	if (d->count >= JOB_ELF_MAX_DEPS)
		return -1;
	snprintf(d->paths[d->count], JOBD_PATH_LEN_LONG, "%s", path);
	d->count++;
	return 0;
}

static int find_soname(const char *soname, const char *runpath,
                       const char *origin, char *out, size_t out_sz)
{
	struct stat st;

	if (runpath && *runpath) {
		char tmp[JOBD_PATH_LEN_LONG];
		snprintf(tmp, sizeof(tmp), "%s", runpath);

		char *save = NULL;
		for (char *tok = strtok_r(tmp, ":", &save); tok;
		     tok = strtok_r(NULL, ":", &save)) {
			char dir[JOBD_PATH_LEN_LONG];
			if (strncmp(tok, "$ORIGIN", 7) == 0)
				snprintf(dir, sizeof(dir), "%s%s", origin, tok + 7);
			else if (strncmp(tok, "${ORIGIN}", 9) == 0)
				snprintf(dir, sizeof(dir), "%s%s", origin, tok + 9);
			else
				snprintf(dir, sizeof(dir), "%s", tok);

			char cand[JOBD_PATH_LEN_LONG];
			int n = snprintf(cand, sizeof(cand), "%s/%s", dir, soname);
			if (n > 0 && (size_t)n < sizeof(cand) &&
			    stat(cand, &st) == 0 && S_ISREG(st.st_mode)) {
				snprintf(out, out_sz, "%s", cand);
				return 0;
			}
		}
	}

	lib_dirs_init();
	for (int i = 0; i < g_lib_dir_count; i++) {
		char cand[JOBD_PATH_LEN_LONG];
		int n = snprintf(cand, sizeof(cand), "%s/%s",
		                 g_lib_dirs[i], soname);
		if (n < 0 || (size_t)n >= sizeof(cand))
			continue;
		if (stat(cand, &st) == 0 && S_ISREG(st.st_mode)) {
			snprintf(out, out_sz, "%s", cand);
			return 0;
		}
	}

	return -1;
}

static void dirname_of(const char *path, char *out, size_t out_sz)
{
	snprintf(out, out_sz, "%s", path);
	char *slash = strrchr(out, '/');
	if (slash && slash != out)
		*slash = '\0';
	else if (slash)
		out[1] = '\0';
	else
		snprintf(out, out_sz, ".");
}

static void resolve_recursive(const char *binary, struct job_elf_deps *out,
                              int depth)
{
	if (depth > 8 || out->count >= JOB_ELF_MAX_DEPS)
		return;

	int fd = open(binary, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	struct elf_info info;
	char err[128];
	if (parse_headers(fd, &info, err, sizeof(err)) != 0) {
		close(fd);
		return;
	}

	struct dyn_result dyn;
	parse_dynamic(fd, &info, &dyn);

	if (depth == 0 && info.interp_size > 0 &&
	    info.interp_size < JOBD_PATH_LEN_LONG) {
		char interp[JOBD_PATH_LEN_LONG];
		if (read_string_at(fd, info.interp_off, interp,
		                   sizeof(interp)) == 0)
			snprintf(out->interp, sizeof(out->interp), "%s", interp);
	}

	close(fd);

	char origin[JOBD_PATH_LEN_LONG];
	dirname_of(binary, origin, sizeof(origin));

	for (int i = 0; i < dyn.needed_count; i++) {
		char path[JOBD_PATH_LEN_LONG];
		if (find_soname(dyn.needed[i], dyn.runpath, origin,
		                path, sizeof(path)) != 0)
			continue;
		int rc = deps_add(out, path);
		if (rc == 0)
			resolve_recursive(path, out, depth + 1);
	}
}

int job_elf_resolve_deps(const char *binary, struct job_elf_deps *out,
                           char *err, size_t err_sz)
{
	memset(out, 0, sizeof(*out));

	int fd = open(binary, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(err, err_sz, "cannot open %s: %s", binary, strerror(errno));
		return -1;
	}

	struct elf_info info;
	if (parse_headers(fd, &info, err, err_sz) != 0) {
		close(fd);
		return -1;
	}
	close(fd);

	resolve_recursive(binary, out, 0);

	if (out->interp[0] && !deps_contains(out, out->interp)) {
		struct stat st;
		if (stat(out->interp, &st) == 0 && S_ISREG(st.st_mode))
			deps_add(out, out->interp);
	}

	return 0;
}
