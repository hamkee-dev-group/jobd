#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#define MAX_ALLOW        64
#define MAX_HOST         256
#define IO_BUF           16384

struct allow_entry {
	char     host[MAX_HOST];
	uint16_t port;
};

static struct allow_entry g_allow[MAX_ALLOW];
static int  g_allow_count;
static int  g_verbose;

static volatile sig_atomic_t g_stop;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void logmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "job-netd: ");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	fflush(stderr);
}

static int allow_add(const char *spec)
{
	if (g_allow_count >= MAX_ALLOW)
		return -1;

	const char *colon = strrchr(spec, ':');
	if (!colon || colon == spec)
		return -1;

	size_t hlen = (size_t)(colon - spec);
	if (hlen >= MAX_HOST)
		return -1;

	char *end = NULL;
	errno = 0;
	unsigned long port = strtoul(colon + 1, &end, 10);
	if (errno != 0 || !end || *end != '\0' || port == 0 || port > 65535)
		return -1;

	memcpy(g_allow[g_allow_count].host, spec, hlen);
	g_allow[g_allow_count].host[hlen] = '\0';
	g_allow[g_allow_count].port = (uint16_t)port;
	g_allow_count++;
	return 0;
}

static int host_eq(const char *a, const char *b)
{
	while (*a && *b) {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
		a++; b++;
	}
	return *a == '\0' && *b == '\0';
}

static int allow_match(const char *host, uint16_t port)
{
	for (int i = 0; i < g_allow_count; i++) {
		if (g_allow[i].port == port && host_eq(g_allow[i].host, host))
			return 1;
	}
	return 0;
}

static int address_is_permitted(const struct sockaddr *sa, const char *host)
{
	char literal[INET6_ADDRSTRLEN];

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
		uint32_t a = ntohl(in->sin_addr.s_addr);

		int blocked = ((a >> 24) == 127) ||
		              ((a >> 24) == 0)   ||
		              ((a & 0xFFFF0000u) == 0xA9FE0000u) ||
		              ((a >> 28) == 0xE) ||
		              (a == 0xFFFFFFFFu);
		if (!blocked)
			return 1;

		if (!inet_ntop(AF_INET, &in->sin_addr, literal, sizeof(literal)))
			return 0;
		return host_eq(literal, host);
	}

	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
		const unsigned char *b = in6->sin6_addr.s6_addr;

		int blocked = IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) ||
		              IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr) ||
		              IN6_IS_ADDR_MULTICAST(&in6->sin6_addr) ||
		              IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr) ||
		              (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr) && b[12] == 127);
		if (!blocked)
			return 1;

		if (!inet_ntop(AF_INET6, &in6->sin6_addr, literal, sizeof(literal)))
			return 0;
		return host_eq(literal, host);
	}

	return 0;
}

static void pump(int a, int b)
{
	struct pollfd pfd[2];
	char buf[IO_BUF];

	pfd[0].fd = a;
	pfd[1].fd = b;

	while (1) {
		pfd[0].events = POLLIN;
		pfd[1].events = POLLIN;

		int n = poll(pfd, 2, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return;
		}

		for (int i = 0; i < 2; i++) {
			if (!pfd[i].revents)
				continue;

			int from = pfd[i].fd;
			int to   = pfd[1 - i].fd;

			if (pfd[i].revents & POLLIN) {
				ssize_t got = read(from, buf, sizeof(buf));
				if (got > 0) {
					ssize_t off = 0;
					while (off < got) {
						ssize_t w = write(to, buf + off,
						                  (size_t)(got - off));
						if (w < 0) {
							if (errno == EINTR)
								continue;
							return;
						}
						off += w;
					}
					continue;
				}
				if (got < 0 && (errno == EINTR || errno == EAGAIN))
					continue;
				return;
			}

			if (pfd[i].revents & (POLLHUP | POLLERR | POLLNVAL))
				return;
		}
	}
}

static int read_full(int fd, void *buf, size_t n)
{
	unsigned char *p = buf;
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
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

static int write_full(int fd, const void *buf, size_t n)
{
	const unsigned char *p = buf;
	size_t sent = 0;
	while (sent < n) {
		ssize_t w = write(fd, p + sent, n - sent);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)w;
	}
	return 0;
}

#define SOCKS_VER  0x05
#define SOCKS_CONNECT 0x01
#define SOCKS_ATYP_IPV4   0x01
#define SOCKS_ATYP_DOMAIN 0x03
#define SOCKS_ATYP_IPV6   0x04

#define SOCKS_OK            0x00
#define SOCKS_FAIL          0x01
#define SOCKS_NOT_ALLOWED   0x02
#define SOCKS_HOST_UNREACH  0x04
#define SOCKS_CMD_UNSUP     0x07
#define SOCKS_ATYP_UNSUP    0x08

static void socks_reply(int fd, unsigned char code)
{
	unsigned char r[10] = { SOCKS_VER, code, 0x00, SOCKS_ATYP_IPV4,
	                        0, 0, 0, 0, 0, 0 };
	write_full(fd, r, sizeof(r));
}

static int connect_target(const char *host, uint16_t port, unsigned char *code)
{
	char portstr[8];
	snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
		*code = SOCKS_HOST_UNREACH;
		return -1;
	}

	int out = -1;
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		if (!address_is_permitted(ai->ai_addr, host)) {
			logmsg("refused %s:%u: resolves to a restricted address",
			       host, (unsigned)port);
			*code = SOCKS_NOT_ALLOWED;
			continue;
		}

		int s = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
		               ai->ai_protocol);
		if (s < 0)
			continue;

		if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
			out = s;
			break;
		}
		close(s);
		*code = SOCKS_HOST_UNREACH;
	}

	freeaddrinfo(res);
	return out;
}

static void broker_serve(int fd)
{
	unsigned char hdr[4];

	if (read_full(fd, hdr, 2) != 0 || hdr[0] != SOCKS_VER)
		return;

	unsigned int nmethods = hdr[1];
	unsigned char methods[256];
	if (nmethods > 0 && read_full(fd, methods, nmethods) != 0)
		return;

	unsigned char greet[2] = { SOCKS_VER, 0x00 };
	if (write_full(fd, greet, sizeof(greet)) != 0)
		return;

	if (read_full(fd, hdr, 4) != 0 || hdr[0] != SOCKS_VER)
		return;

	if (hdr[1] != SOCKS_CONNECT) {
		socks_reply(fd, SOCKS_CMD_UNSUP);
		return;
	}

	char host[MAX_HOST];
	host[0] = '\0';

	switch (hdr[3]) {
	case SOCKS_ATYP_IPV4: {
		unsigned char a[4];
		if (read_full(fd, a, 4) != 0)
			return;
		if (!inet_ntop(AF_INET, a, host, sizeof(host)))
			return;
		break;
	}
	case SOCKS_ATYP_IPV6: {
		unsigned char a[16];
		if (read_full(fd, a, 16) != 0)
			return;
		if (!inet_ntop(AF_INET6, a, host, sizeof(host)))
			return;
		break;
	}
	case SOCKS_ATYP_DOMAIN: {

		unsigned char len;
		if (read_full(fd, &len, 1) != 0 || len == 0)
			return;
		if (read_full(fd, host, len) != 0)
			return;
		host[len] = '\0';
		break;
	}
	default:
		socks_reply(fd, SOCKS_ATYP_UNSUP);
		return;
	}

	unsigned char pb[2];
	if (read_full(fd, pb, 2) != 0)
		return;
	uint16_t port = (uint16_t)((pb[0] << 8) | pb[1]);

	if (!allow_match(host, port)) {
		logmsg("denied %s:%u", host, (unsigned)port);
		socks_reply(fd, SOCKS_NOT_ALLOWED);
		return;
	}

	unsigned char code = SOCKS_FAIL;
	int out = connect_target(host, port, &code);
	if (out < 0) {
		logmsg("could not reach %s:%u", host, (unsigned)port);
		socks_reply(fd, code);
		return;
	}

	if (g_verbose)
		logmsg("allowed %s:%u", host, (unsigned)port);

	socks_reply(fd, SOCKS_OK);
	pump(fd, out);
	close(out);
}

static int broker_main(const char *sock_path)
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (srv < 0) {
		logmsg("socket: %s", strerror(errno));
		return 1;
	}

	unlink(sock_path);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(sock_path) >= sizeof(addr.sun_path)) {
		logmsg("socket path too long");
		return 1;
	}
	memcpy(addr.sun_path, sock_path, strlen(sock_path));

	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		logmsg("bind %s: %s", sock_path, strerror(errno));
		return 1;
	}
	chmod(sock_path, 0666);

	if (listen(srv, 16) < 0) {
		logmsg("listen: %s", strerror(errno));
		return 1;
	}

	logmsg("broker ready on %s (%d destination(s) allowed)",
	       sock_path, g_allow_count);

	while (!g_stop) {
		int c = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
		if (c < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		pid_t p = fork();
		if (p == 0) {
			close(srv);
			broker_serve(c);
			close(c);
			_exit(0);
		}
		close(c);
		if (p < 0)
			logmsg("fork: %s", strerror(errno));
	}

	close(srv);
	unlink(sock_path);
	return 0;
}

static int relay_connect_broker(const char *sock_path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(sock_path) >= sizeof(addr.sun_path)) {
		close(fd);
		return -1;
	}
	memcpy(addr.sun_path, sock_path, strlen(sock_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void relay_loop(int srv, const char *sock_path)
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	while (!g_stop) {
		int c = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
		if (c < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		pid_t p = fork();
		if (p == 0) {
			close(srv);
			int up = relay_connect_broker(sock_path);
			if (up >= 0) {
				pump(c, up);
				close(up);
			}
			close(c);
			_exit(0);
		}
		close(c);
	}

	close(srv);
}

static int loopback_up(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int relay_main(const char *sock_path, uint16_t port,
                      char *const *next_argv)
{

	if (loopback_up() != 0 && g_verbose)
		logmsg("loopback already configured or not permitted: %s",
		       strerror(errno));

	int srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (srv < 0) {
		logmsg("socket: %s", strerror(errno));
		return 1;
	}

	int one = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = htons(port);

	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		logmsg("bind 127.0.0.1:%u: %s", (unsigned)port, strerror(errno));
		return 1;
	}
	if (listen(srv, 16) < 0) {
		logmsg("listen: %s", strerror(errno));
		return 1;
	}

	logmsg("relay listening on 127.0.0.1:%u, forwarding to %s",
	       (unsigned)port, sock_path);

	pid_t p = fork();
	if (p < 0) {
		logmsg("fork: %s", strerror(errno));
		return 1;
	}

	if (p == 0) {

		prctl(PR_SET_PDEATHSIG, SIGKILL);
		signal(SIGINT, on_signal);
		signal(SIGTERM, on_signal);
		relay_loop(srv, sock_path);
		_exit(0);
	}

	close(srv);

	if (!next_argv || !next_argv[0]) {

		int status;
		while (waitpid(p, &status, 0) < 0 && errno == EINTR)
			;
		return 0;
	}

	execv(next_argv[0], next_argv);
	logmsg("exec(%s) failed: %s", next_argv[0], strerror(errno));
	return 127;
}

static void usage(void)
{
	fprintf(stderr,
	  "usage:\n"
	  "  job-netd broker --socket PATH --allow HOST:PORT [--allow ...]\n"
	  "  job-netd relay  --socket PATH --port N [--] COMMAND [ARGS...]\n"
	  "\n"
	  "broker runs in the host network namespace and permits only the\n"
	  "listed destinations.  relay runs inside the job's namespace, binds\n"
	  "127.0.0.1:N, forwards to the broker's socket and execs COMMAND.\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		return 1;
	}

	const char *mode = argv[1];
	const char *sock_path = NULL;
	long port = 0;
	int child_start = -1;

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			child_start = i + 1;
			break;
		}
		if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
			sock_path = argv[++i];
		} else if (strcmp(argv[i], "--allow") == 0 && i + 1 < argc) {
			if (allow_add(argv[++i]) != 0) {
				fprintf(stderr,
				        "job-netd: bad --allow value: %s "
				        "(expected HOST:PORT)\n", argv[i]);
				return 1;
			}
		} else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			char *end = NULL;
			errno = 0;
			port = strtol(argv[++i], &end, 10);
			if (errno != 0 || !end || *end != '\0' ||
			    port <= 0 || port > 65535) {
				fprintf(stderr, "job-netd: bad --port value\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--verbose") == 0) {
			g_verbose = 1;
		} else {
			fprintf(stderr, "job-netd: unexpected argument: %s\n",
			        argv[i]);
			usage();
			return 1;
		}
	}

	if (!sock_path) {
		fprintf(stderr, "job-netd: --socket is required\n");
		return 1;
	}

	if (strcmp(mode, "broker") == 0) {
		if (g_allow_count == 0) {

			fprintf(stderr,
			        "job-netd: broker needs at least one --allow\n");
			return 1;
		}
		signal(SIGINT, on_signal);
		signal(SIGTERM, on_signal);
		return broker_main(sock_path);
	}

	if (strcmp(mode, "relay") == 0) {
		if (port == 0) {
			fprintf(stderr, "job-netd: relay needs --port\n");
			return 1;
		}
		char *const *next = (child_start > 0 && child_start < argc)
		                  ? &argv[child_start] : NULL;
		return relay_main(sock_path, (uint16_t)port, next);
	}

	usage();
	return 1;
}
