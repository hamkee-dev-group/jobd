#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "jobd.h"
#include "state.h"

#define RESP_BUF_BYTES  (64 * 1024)
#define CLIENT_TIMEOUT_SEC 10
#define LOOP_TIMEOUT_MS 500

enum ev_kind {
	EV_LISTEN = 1,
	EV_PIDFD,
	EV_TIMER,
	EV_INOTIFY,
	EV_WAITER,
};

struct ev_src {
	enum ev_kind      kind;
	int               fd;
	struct job_entry *job;
};

static int g_epoll_fd  = -1;
static int g_listen_fd = -1;
static int g_inotify_fd = -1;
static volatile sig_atomic_t g_stop;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static struct ev_src *ev_new(enum ev_kind kind, int fd, struct job_entry *job)
{
	struct ev_src *s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;
	s->kind = kind;
	s->fd   = fd;
	s->job  = job;
	return s;
}

static int ev_add(int fd, uint32_t events, struct ev_src *src)
{
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events   = events;
	ev.data.ptr = src;
	return epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static void ev_del(int fd)
{
	epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static int peer_authorised(int fd, char *who, size_t who_sz)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 ||
	    len != sizeof(cred)) {
		snprintf(who, who_sz, "unknown peer");
		return 0;
	}

	snprintf(who, who_sz, "pid=%d uid=%u gid=%u",
	         (int)cred.pid, (unsigned)cred.uid, (unsigned)cred.gid);

	const struct jobd_access *acc = jobd_access();

	for (int i = 0; i < acc->allow_uid_count; i++) {
		if (cred.uid == acc->allow_uid[i])
			return 1;
	}
	for (int i = 0; i < acc->allow_gid_count; i++) {
		if (cred.gid == acc->allow_gid[i])
			return 1;
	}

	return 0;
}

static void waiter_close(struct job_entry *e, int idx)
{
	int fd = e->waiters[idx].fd;
	if (fd >= 0) {
		ev_del(fd);
		close(fd);
	}
	for (int i = idx; i < e->waiter_count - 1; i++)
		e->waiters[i] = e->waiters[i + 1];
	e->waiter_count--;
}

static void job_result_text(const struct job_entry *e, char *out, size_t out_sz)
{
	struct agd_buf b;
	agd_buf_init(&b, out, out_sz);
	agd_buf_addf(&b,
	             "id: %s\nstate: %s\nexit_code: %u\nexit_signal: %u\n"
	             "reason: %s\n",
	             e->job.id, job_state_name(e->job.state),
	             e->job.exit_code, e->job.exit_signal,
	             job_exit_reason_name(e->job.exit_reason));
}

static void notify_waiters(struct job_entry *e)
{
	char result[512];
	job_result_text(e, result, sizeof(result));

	while (e->waiter_count > 0) {
		struct job_waiter w = e->waiters[0];
		jobd_send_response(w.fd, w.request_id, JOBD_STATUS_OK,
		                     (const uint8_t *)result,
		                     (uint32_t)strlen(result));
		waiter_close(e, 0);
	}
}

static void job_finished(struct job_entry *e, int wstatus)
{
	if (e->pidfd >= 0)
		ev_del(e->pidfd);
	if (e->timer_fd >= 0)
		ev_del(e->timer_fd);
	if (e->log_wd >= 0 && g_inotify_fd >= 0) {
		inotify_rm_watch(g_inotify_fd, e->log_wd);
		e->log_wd = -1;
	}

	job_monitor_scan_alerts(e);

	job_reaped(e, wstatus);
	notify_waiters(e);
}

static void job_check_exit(struct job_entry *e)
{
	if (e->child_pid <= 0)
		return;

	int status = 0;
	pid_t w = waitpid(e->child_pid, &status, WNOHANG);
	if (w == e->child_pid)
		job_finished(e, status);
	else if (w < 0 && errno == ECHILD)
		job_finished(e, 0);
}

static void sweep_running(struct job_entry *e, void *ctx)
{
	(void)ctx;
	if (e->job.state == JOB_RUNNING)
		job_check_exit(e);
}

static int payload_job_id(const uint8_t *buf, size_t len, char *out,
                          size_t out_sz, char *err, size_t err_sz)
{
	if (len == 0) {
		snprintf(err, err_sz, "missing job ID");
		return -1;
	}
	if (len >= out_sz) {
		snprintf(err, err_sz, "job ID too long");
		return -1;
	}

	memcpy(out, buf, len);
	out[len] = '\0';

	if (strlen(out) != len) {
		snprintf(err, err_sz, "job ID contains a NUL byte");
		return -1;
	}

	return job_id_validate(out, err, err_sz);
}

static void send_err(int fd, uint64_t rid, int status, const char *msg)
{
	jobd_send_response(fd, rid, status, (const uint8_t *)msg,
	                     (uint32_t)strlen(msg));
}

struct list_ctx {
	struct agd_buf *b;
};

static void list_each(struct job_entry *e, void *ctx)
{
	struct list_ctx *lc = ctx;
	agd_buf_addf(lc->b, "  %-24s %-12s exit=%u signal=%u\n",
	             e->job.id, job_state_name(e->job.state),
	             e->job.exit_code, e->job.exit_signal);
}

static void handle_run(int fd, const struct jobd_msg_header *hdr,
                       const uint8_t *buf, size_t len, char *resp)
{
	struct job job;
	char err[512];

	if (jobd_decode_run_request(buf, len, &job, err, sizeof(err)) != 0) {
		jobd_log("run: malformed request: %s", err);
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_PROTOCOL, err);
		return;
	}

	if (job_validate(&job, err, sizeof(err)) != 0) {
		jobd_log("run: rejected job %s: %s", job.id, err);
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_VALIDATE, err);
		return;
	}

	if (job_features_check(&job, err, sizeof(err)) != 0) {
		jobd_log("run: rejected job %s: %s", job.id, err);
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_PERM, err);
		return;
	}

	if (job.dry_run) {
		jobd_policy_plan_dryrun(&job, resp, RESP_BUF_BYTES);
		jobd_send_response(fd, hdr->request_id, JOBD_STATUS_OK,
		                     (const uint8_t *)resp,
		                     (uint32_t)strlen(resp));
		return;
	}

	struct job_entry *existing = job_table_find(job.id);
	if (existing && !job_state_is_terminal(existing->job.state)) {
		snprintf(err, sizeof(err), "job %s is already %s", job.id,
		         job_state_name(existing->job.state));
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_CONFLICT, err);
		return;
	}
	if (existing)
		job_table_remove(job.id);

	struct job_entry *e = job_table_add(&job);
	if (!e) {
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_INTERNAL,
		         "out of memory");
		return;
	}

	struct agd_buf out;
	agd_buf_init(&out, resp, RESP_BUF_BYTES);

	int rc = job_launch(e, &out);

	job_state_save(&e->job, err, sizeof(err));

	if (rc != 0) {
		jobd_send_response(fd, hdr->request_id, JOBD_STATUS_ERR_SETUP,
		                     (const uint8_t *)resp,
		                     (uint32_t)agd_buf_len(&out));
		return;
	}

	if (e->pidfd >= 0) {
		struct ev_src *s = ev_new(EV_PIDFD, e->pidfd, e);
		if (s)
			ev_add(e->pidfd, EPOLLIN, s);
	}
	if (e->timer_fd >= 0) {
		struct ev_src *s = ev_new(EV_TIMER, e->timer_fd, e);
		if (s)
			ev_add(e->timer_fd, EPOLLIN, s);
	}
	if (g_inotify_fd >= 0 && e->job.fanotify_mode != JOBD_FANOTIFY_OFF &&
	    e->job.log_dir[0]) {
		e->log_wd = inotify_add_watch(g_inotify_fd, e->job.log_dir,
		                              IN_MODIFY | IN_CREATE);
	}

	jobd_send_response(fd, hdr->request_id, JOBD_STATUS_OK,
	                     (const uint8_t *)resp,
	                     (uint32_t)agd_buf_len(&out));
}

static int handle_wait(int fd, const struct jobd_msg_header *hdr,
                       struct job_entry *e)
{
	if (job_state_is_terminal(e->job.state)) {
		char result[512];
		job_result_text(e, result, sizeof(result));
		jobd_send_response(fd, hdr->request_id, JOBD_STATUS_OK,
		                     (const uint8_t *)result,
		                     (uint32_t)strlen(result));
		return 0;
	}

	if (e->waiter_count >= MAX_JOB_WAITERS) {
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_CONFLICT,
		         "too many waiters for this job");
		return 0;
	}

	struct ev_src *s = ev_new(EV_WAITER, fd, e);
	if (!s || ev_add(fd, EPOLLRDHUP | EPOLLHUP, s) != 0) {
		free(s);
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_INTERNAL,
		         "cannot register waiter");
		return 0;
	}

	e->waiters[e->waiter_count].fd         = fd;
	e->waiters[e->waiter_count].request_id = hdr->request_id;
	e->waiter_count++;
	return 1;
}

static void handle_logs(int fd, const struct jobd_msg_header *hdr,
                        const char *jid, char *resp)
{
	struct agd_buf b;
	agd_buf_init(&b, resp, RESP_BUF_BYTES);

	int found = 0;

	char paths[4][JOBD_PATH_LEN_LONG];
	const char *labels[4];
	int count = 0;

	if (snprintf(paths[count], sizeof(paths[0]), "%s/%s.log",
	             jobd_paths()->cgroup_log_dir, jid) <
	    (int)sizeof(paths[0])) {
		labels[count] = "workload output";
		count++;
	}

	static const char *job_files[] = {
		"logs/cgroup.result", "logs/fanotifyd.jsonl", NULL
	};
	for (int i = 0; job_files[i] && count < 4; i++) {
		if (jobd_job_subdir(jid, job_files[i], paths[count],
		                      sizeof(paths[0])) != 0)
			continue;
		labels[count] = job_files[i];
		count++;
	}

	for (int i = 0; i < count; i++) {
		int lfd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (lfd < 0)
			continue;

		found = 1;
		agd_buf_addf(&b, "=== %s ===\n", labels[i]);

		char chunk[4096];
		ssize_t n;
		while ((n = read(lfd, chunk, sizeof(chunk) - 1)) > 0) {
			chunk[n] = '\0';
			agd_buf_adds(&b, chunk);
			if (agd_buf_truncated(&b))
				break;
		}
		close(lfd);
		agd_buf_addch(&b, '\n');
	}

	if (!found) {
		send_err(fd, hdr->request_id, JOBD_STATUS_ERR_NOTFOUND,
		         "no logs for this job");
		return;
	}

	jobd_send_response(fd, hdr->request_id, JOBD_STATUS_OK,
	                     (const uint8_t *)resp, (uint32_t)agd_buf_len(&b));
}

static int handle_request(int fd, char *resp)
{
	uint8_t *buf = malloc(JOBD_MAX_PAYLOAD);
	if (!buf)
		return 0;

	struct jobd_msg_header hdr;
	size_t len = 0;

	int rc = jobd_recv_msg(fd, &hdr, buf, JOBD_MAX_PAYLOAD, &len);
	if (rc != 0) {
		jobd_log("protocol error: recv rc=%d", rc);
		jobd_send_response(fd, 0, JOBD_STATUS_ERR_PROTOCOL, NULL, 0);
		free(buf);
		return 0;
	}

	char jid[JOBD_MAX_JOB_ID + 1];
	char err[512];
	int retained = 0;

	switch (hdr.type) {
	case JOBD_MSG_RUN:
		handle_run(fd, &hdr, buf, len, resp);
		break;

	case JOBD_MSG_DOCTOR:
		jobd_doctor(resp, RESP_BUF_BYTES);
		jobd_send_response(fd, hdr.request_id, JOBD_STATUS_OK,
		                     (const uint8_t *)resp,
		                     (uint32_t)strlen(resp));
		break;

	case JOBD_MSG_LIST: {
		struct agd_buf b;
		agd_buf_init(&b, resp, RESP_BUF_BYTES);
		agd_buf_addf(&b, "%d job(s):\n", job_table_size());
		struct list_ctx lc = { &b };
		job_table_foreach(list_each, &lc);
		jobd_send_response(fd, hdr.request_id, JOBD_STATUS_OK,
		                     (const uint8_t *)resp,
		                     (uint32_t)agd_buf_len(&b));
		break;
	}

	case JOBD_MSG_INSPECT:
	case JOBD_MSG_WAIT:
	case JOBD_MSG_LOGS:
	case JOBD_MSG_KILL:
	case JOBD_MSG_CLEANUP: {
		if (payload_job_id(buf, len, jid, sizeof(jid),
		                   err, sizeof(err)) != 0) {
			send_err(fd, hdr.request_id, JOBD_STATUS_ERR_VALIDATE, err);
			break;
		}

		if (hdr.type == JOBD_MSG_LOGS) {
			handle_logs(fd, &hdr, jid, resp);
			break;
		}

		struct job_entry *e = job_table_find(jid);
		if (!e) {
			send_err(fd, hdr.request_id, JOBD_STATUS_ERR_NOTFOUND,
			         "no such job");
			break;
		}

		if (hdr.type == JOBD_MSG_INSPECT) {
			struct agd_buf b;
			agd_buf_init(&b, resp, RESP_BUF_BYTES);

			char display[4096];
			job_argv_display(&e->job, display, sizeof(display));

			agd_buf_addf(&b,
			             "id: %s\nstate: %s\nexit_code: %u\n"
			             "exit_signal: %u\nexit_reason: %s\n"
			             "argv: %s\npids_max: %u\ntimeout_ms: %llu\n"
			             "root: %s\npolicy: %s\nlogs: %s\n",
			             e->job.id, job_state_name(e->job.state),
			             e->job.exit_code, e->job.exit_signal,
			             job_exit_reason_name(e->job.exit_reason),
			             display, e->job.pids_max,
			             (unsigned long long)e->job.timeout_ms,
			             e->job.root_path, e->job.policy_path,
			             e->job.log_dir);
			jobd_send_response(fd, hdr.request_id, JOBD_STATUS_OK,
			                     (const uint8_t *)resp,
			                     (uint32_t)agd_buf_len(&b));
		} else if (hdr.type == JOBD_MSG_WAIT) {
			retained = handle_wait(fd, &hdr, e);
		} else if (hdr.type == JOBD_MSG_KILL) {
			if (job_state_is_terminal(e->job.state)) {
				send_err(fd, hdr.request_id, JOBD_STATUS_OK,
				         "job already finished");
				break;
			}
			if (job_react(e, JOB_REACT_KILL, err, sizeof(err)) != 0) {
				send_err(fd, hdr.request_id,
				         JOBD_STATUS_ERR_INTERNAL, err);
			} else {
				send_err(fd, hdr.request_id, JOBD_STATUS_OK, err);
			}
		} else {
			if (!job_state_is_terminal(e->job.state)) {
				job_react(e, JOB_REACT_KILL, err, sizeof(err));
				job_check_exit(e);
			}
			notify_waiters(e);
			job_cleanup_job(e);
			job_state_delete(jid);
			job_table_remove(jid);
			send_err(fd, hdr.request_id, JOBD_STATUS_OK, "cleaned");
		}
		break;
	}

	default:
		jobd_log("unknown message type %u", hdr.type);
		jobd_send_response(fd, hdr.request_id,
		                     JOBD_STATUS_ERR_PROTOCOL, NULL, 0);
		break;
	}

	free(buf);
	return retained;
}

static void scan_if_watched(struct job_entry *e, void *ctx)
{
	int wd = *(const int *)ctx;
	if (e->log_wd >= 0 && e->log_wd == wd)
		job_monitor_scan_alerts(e);
}

static void handle_inotify(void)
{
	union {
		struct inotify_event ev;
		char buf[4096];
	} u;

	ssize_t n = read(g_inotify_fd, u.buf, sizeof(u.buf));
	if (n <= 0)
		return;

	size_t off = 0;
	while (off + sizeof(struct inotify_event) <= (size_t)n) {
		struct inotify_event *ev = (struct inotify_event *)(u.buf + off);
		size_t rec = sizeof(struct inotify_event) + ev->len;
		if (off + rec > (size_t)n)
			break;

		int wd = ev->wd;
		job_table_foreach(scan_if_watched, &wd);
		off += rec;
	}
}

static void accept_client(char *resp)
{
	struct sockaddr_un addr;
	socklen_t alen = sizeof(addr);

	int cfd = accept4(g_listen_fd, (struct sockaddr *)&addr, &alen,
	                  SOCK_CLOEXEC);
	if (cfd < 0) {
		if (errno != EINTR && errno != EAGAIN)
			jobd_log("accept: %s", strerror(errno));
		return;
	}

	char who[128];
	if (!peer_authorised(cfd, who, sizeof(who))) {
		jobd_log("rejected connection from %s", who);
		send_err(cfd, 0, JOBD_STATUS_ERR_PERM,
		         "not authorised to control jobd");
		close(cfd);
		return;
	}

	struct timeval tv = { .tv_sec = CLIENT_TIMEOUT_SEC, .tv_usec = 0 };
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if (!handle_request(cfd, resp))
		close(cfd);
}

static int setup_listener(void)
{
	const struct jobd_paths *p = jobd_paths();

	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		jobd_log("socket: %s", strerror(errno));
		return -1;
	}

	unlink(p->socket_path);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(p->socket_path) >= sizeof(addr.sun_path)) {
		jobd_log("socket path too long: %s", p->socket_path);
		close(fd);
		return -1;
	}
	memcpy(addr.sun_path, p->socket_path, strlen(p->socket_path));

	mode_t old = umask(0177);
	int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	umask(old);

	if (rc < 0) {
		jobd_log("bind %s: %s", p->socket_path, strerror(errno));
		close(fd);
		return -1;
	}

	const struct jobd_access *acc = jobd_access();
	if (acc->allow_gid_count > 0) {
		if (chown(p->socket_path, 0, acc->allow_gid[0]) != 0)
			jobd_log("warning: chown %s: %s", p->socket_path,
			           strerror(errno));
		chmod(p->socket_path, 0660);
	} else if (acc->allow_uid_count > 1 || acc->allow_uid[0] != 0) {
		chmod(p->socket_path, 0666);
	} else {
		chmod(p->socket_path, 0600);
	}

	if (listen(fd, 64) < 0) {
		jobd_log("listen: %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int jobd_run_daemon(const struct jobd_runtime *rt)
{
	(void)rt;

	g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (g_epoll_fd < 0) {
		jobd_log("epoll_create1: %s", strerror(errno));
		return 1;
	}

	g_listen_fd = setup_listener();
	if (g_listen_fd < 0)
		return 1;

	g_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (g_inotify_fd < 0)
		jobd_log("warning: inotify unavailable (%s); monitored jobs "
		           "will be rejected", strerror(errno));

	struct ev_src *ls = ev_new(EV_LISTEN, g_listen_fd, NULL);
	if (!ls || ev_add(g_listen_fd, EPOLLIN, ls) != 0) {
		jobd_log("cannot register the listening socket");
		return 1;
	}
	if (g_inotify_fd >= 0) {
		struct ev_src *is = ev_new(EV_INOTIFY, g_inotify_fd, NULL);
		if (is && ev_add(g_inotify_fd, EPOLLIN, is) == 0) {
			job_inotify_set_ready(1);
		} else {
			jobd_log("warning: cannot register inotify with the "
			           "event loop (%s); monitored jobs will be "
			           "rejected", strerror(errno));
			free(is);
		}
	}

	char *resp = malloc(RESP_BUF_BYTES);
	if (!resp) {
		jobd_log("out of memory");
		return 1;
	}

	jobd_log("listening on %s", jobd_paths()->socket_path);

	while (!g_stop) {
		struct epoll_event events[16];
		int n = epoll_wait(g_epoll_fd, events, 16, LOOP_TIMEOUT_MS);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			jobd_log("epoll_wait: %s", strerror(errno));
			break;
		}

		for (int i = 0; i < n; i++) {
			struct ev_src *s = events[i].data.ptr;
			if (!s)
				continue;

			switch (s->kind) {
			case EV_LISTEN:
				accept_client(resp);
				break;

			case EV_PIDFD:
				job_check_exit(s->job);
				break;

			case EV_TIMER: {
				uint64_t ticks;
				ssize_t r = read(s->fd, &ticks, sizeof(ticks));
				(void)r;
				if (job_state_is_terminal(s->job->job.state))
					break;
				jobd_log("job %s exceeded its %llu ms deadline",
				           s->job->job.id,
				           (unsigned long long)s->job->job.timeout_ms);
				s->job->job.exit_reason = JOB_EXIT_TIMEOUT;
				char err[256];
				job_react(s->job, JOB_REACT_KILL, err, sizeof(err));
				break;
			}

			case EV_INOTIFY:
				handle_inotify();
				break;

			case EV_WAITER: {

				struct job_entry *e = s->job;
				for (int k = 0; k < e->waiter_count; k++) {
					if (e->waiters[k].fd == s->fd) {
						waiter_close(e, k);
						break;
					}
				}
				free(s);
				break;
			}
			}
		}

		job_table_foreach(sweep_running, NULL);
	}

	jobd_log("shutting down");
	free(resp);
	unlink(jobd_paths()->socket_path);
	return 0;
}

static void usage(const char *prog)
{
	printf("usage: %s [options]\n"
	       "\n"
	       "options:\n"
	       "  --config PATH          configuration file\n"
	       "                         (default %s)\n"
	       "  --socket PATH          control socket path\n"
	       "  --component NAME=PATH  location of a component binary\n"
	       "  --set KEY=VALUE        any configuration key\n"
	       "  --foreground           stay in the foreground (default)\n"
	       "  --debug                verbose logging\n"
	       "  --help                 this message\n"
	       "\n"
	       "Component locations are resolved in this order:\n"
	       "  --component, config file, JOBD_<NAME>, then the search\n"
	       "  path (JOBD_COMPONENT_PATH, else the directory holding\n"
	       "  jobd followed by the standard bin directories).\n",
	       prog, jobd_paths()->config_file);
}

int main(int argc, char *argv[])
{
	struct jobd_runtime rt = { .foreground = 1, .debug = 0 };
	const char *config_path = NULL;
	char err[512];

	jobd_config_init();

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
			config_path = argv[++i];
	}

	if (jobd_config_load_file(config_path, err, sizeof(err)) != 0) {
		fprintf(stderr, "jobd: %s\n", err);
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
			if (jobd_config_set("socket", argv[++i],
			                      err, sizeof(err)) != 0) {
				fprintf(stderr, "jobd: %s\n", err);
				return 1;
			}
		} else if ((strcmp(argv[i], "--component") == 0 ||
		            strcmp(argv[i], "--set") == 0) && i + 1 < argc) {
			char pair[JOBD_PATH_LEN_LONG];
			snprintf(pair, sizeof(pair), "%s", argv[++i]);
			char *eq = strchr(pair, '=');
			if (!eq) {
				fprintf(stderr, "jobd: expected NAME=VALUE: %s\n",
				        pair);
				return 1;
			}
			*eq = '\0';
			if (jobd_config_set(pair, eq + 1, err, sizeof(err)) != 0) {
				fprintf(stderr, "jobd: %s\n", err);
				return 1;
			}
		} else if (strcmp(argv[i], "--foreground") == 0) {
			rt.foreground = 1;
		} else if (strcmp(argv[i], "--debug") == 0) {
			rt.debug = 1;
		} else if (strcmp(argv[i], "--help") == 0 ||
		           strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "jobd: unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	jobd_log_set_debug(rt.debug);

	if (job_sandbox_check_caps(err, sizeof(err)) != 0) {
		fprintf(stderr, "jobd: %s\n", err);
		return 1;
	}

	const struct jobd_paths *p = jobd_paths();
	if (mkdir(p->runtime_dir, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "jobd: cannot create %s: %s\n",
		        p->runtime_dir, strerror(errno));
		return 1;
	}
	mkdir(p->state_dir, 0700);
	mkdir(p->jobs_dir, 0700);
	mkdir(p->overlay_dir, 0700);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	job_table_init();
	job_recover_stale_jobs();

	return jobd_run_daemon(&rt);
}
