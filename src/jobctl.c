#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "jobd.h"

#define RESP_MAX (256 * 1024)

static uint64_t g_request_id = 1;

static const char *socket_path(void)
{
	return jobd_paths()->socket_path;
}

static int connect_to_daemon(void)
{
	const char *path = socket_path();

	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t slen = strlen(path);
	if (slen >= sizeof(addr.sun_path)) {
		fprintf(stderr, "socket path too long: %s\n", path);
		close(fd);
		return -1;
	}
	memcpy(addr.sun_path, path, slen);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "cannot connect to %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static int send_request(uint16_t type, const uint8_t *payload,
                        uint32_t payload_len)
{
	int fd = connect_to_daemon();
	if (fd < 0)
		return -1;

	struct jobd_msg_header hdr = {
		.magic       = JOBD_PROTO_MAGIC,
		.version     = JOBD_PROTO_VERSION,
		.type        = type,
		.payload_len = payload_len,
		.request_id  = g_request_id++,
	};

	if (jobd_send_msg(fd, &hdr, payload) != 0) {
		fprintf(stderr, "failed to send the request\n");
		close(fd);
		return -1;
	}

	uint8_t *raw = calloc(1, RESP_MAX);
	if (!raw) {
		fprintf(stderr, "out of memory\n");
		close(fd);
		return -1;
	}

	struct jobd_msg_header rhdr;
	size_t received = 0;
	int rc = jobd_recv_msg(fd, &rhdr, raw, RESP_MAX, &received);
	close(fd);

	if (rc != 0) {
		fprintf(stderr, "protocol error receiving the response (%d)\n", rc);
		free(raw);
		return -1;
	}
	if (rhdr.type != JOBD_MSG_RESPONSE) {
		fprintf(stderr, "unexpected message type: %u\n", rhdr.type);
		free(raw);
		return -1;
	}

	struct jobd_response resp;
	const uint8_t *data = NULL;
	if (jobd_parse_response(raw, received, &resp, &data) != 0) {
		fprintf(stderr, "malformed response\n");
		free(raw);
		return -1;
	}

	int ret = 0;
	if (resp.status != JOBD_STATUS_OK) {
		if (resp.result_len > 0)
			fprintf(stderr, "error: %.*s\n", (int)resp.result_len,
			        (const char *)data);
		else
			fprintf(stderr, "error: status=%d\n", resp.status);
		ret = -1;
	} else if (resp.result_len > 0) {
		fwrite(data, 1, resp.result_len, stdout);
		if (resp.result_len > 0 && data[resp.result_len - 1] != '\n')
			fputc('\n', stdout);
	}

	free(raw);
	return ret;
}

static int copy_field(char *dst, size_t dst_sz, const char *src,
                      const char *what)
{
	if (strlen(src) >= dst_sz) {
		fprintf(stderr, "%s is too long (max %zu bytes)\n", what,
		        dst_sz - 1);
		return -1;
	}
	snprintf(dst, dst_sz, "%s", src);
	return 0;
}

static int cmd_run(int argc, char *argv[])
{
	struct job job;
	job_set_defaults(&job);

	const char *job_id = NULL;
	int dry_run = 0;
	char err[512];

	static struct option long_opts[] = {
		{ "id",          required_argument, 0, 'i'  },
		{ "layer",       required_argument, 0, 'l'  },
		{ "ro",          required_argument, 0, 'R'  },
		{ "rw",          required_argument, 0, 'W'  },
		{ "canary",      required_argument, 0, 'C'  },
		{ "memory-max",  required_argument, 0, 'M'  },
		{ "memory-high", required_argument, 0, 1001 },
		{ "swap-max",    required_argument, 0, 1002 },
		{ "cpu-max",     required_argument, 0, 1003 },
		{ "cpu-weight",  required_argument, 0, 1004 },
		{ "pids-max",    required_argument, 0, 1005 },
		{ "io-weight",   required_argument, 0, 1006 },
		{ "timeout-ms",  required_argument, 0, 1007 },
		{ "network",     required_argument, 0, 1008 },
		{ "fanotify",    required_argument, 0, 1009 },
		{ "memfd-input", required_argument, 0, 1010 },
		{ "iouring",     no_argument,       0, 1011 },
		{ "allow-net",   required_argument, 0, 1012 },
		{ "dry-run",     no_argument,       0, 'n'  },
		{ "env",         required_argument, 0, 'e'  },
		{ 0, 0, 0, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "i:l:R:W:C:M:e:n",
	                          long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i':
			job_id = optarg;
			break;
		case 'l':
			if (job.layer_count >= JOBD_MAX_LAYERS) {
				fprintf(stderr, "too many --layer options (max %u)\n",
				        JOBD_MAX_LAYERS);
				return 1;
			}
			if (copy_field(job.layers[job.layer_count++],
			               JOBD_MAX_PATH_LEN, optarg, "--layer") != 0)
				return 1;
			break;
		case 'R':
			if (job.ro_count >= JOBD_MAX_PATH_COUNT) {
				fprintf(stderr, "too many --ro options (max %u)\n",
				        JOBD_MAX_PATH_COUNT);
				return 1;
			}
			if (copy_field(job.ro_paths[job.ro_count++],
			               JOBD_MAX_PATH_LEN, optarg, "--ro") != 0)
				return 1;
			break;
		case 'W':
			if (job.rw_count >= JOBD_MAX_PATH_COUNT) {
				fprintf(stderr, "too many --rw options (max %u)\n",
				        JOBD_MAX_PATH_COUNT);
				return 1;
			}
			if (copy_field(job.rw_paths[job.rw_count++],
			               JOBD_MAX_PATH_LEN, optarg, "--rw") != 0)
				return 1;
			break;
		case 'C':
			if (job.canary_count >= JOBD_MAX_CANARIES) {
				fprintf(stderr, "too many --canary options (max %u)\n",
				        JOBD_MAX_CANARIES);
				return 1;
			}
			if (copy_field(job.canaries[job.canary_count++],
			               JOBD_MAX_PATH_LEN, optarg, "--canary") != 0)
				return 1;
			break;
		case 'M':   job.memory_max  = strtoull(optarg, NULL, 10); break;
		case 1001:  job.memory_high = strtoull(optarg, NULL, 10); break;
		case 1002:  job.swap_max    = strtoull(optarg, NULL, 10); break;
		case 1003: {

			char tmp[128];
			snprintf(tmp, sizeof(tmp), "%s", optarg);
			char *sep = strpbrk(tmp, "/ ");
			if (!sep) {
				fprintf(stderr,
				        "--cpu-max expects QUOTA/PERIOD, e.g. 100000/100000\n");
				return 1;
			}
			*sep = '\0';
			job.cpu_max_q = strtoull(tmp, NULL, 10);
			job.cpu_max_p = strtoull(sep + 1, NULL, 10);
			if (job.cpu_max_p == 0) {
				fprintf(stderr, "--cpu-max period must be non-zero\n");
				return 1;
			}
			break;
		}
		case 1004:  job.cpu_weight = (uint32_t)strtoul(optarg, NULL, 10); break;
		case 1005:  job.pids_max   = (uint32_t)strtoul(optarg, NULL, 10); break;
		case 1006:  job.io_weight  = (uint32_t)strtoul(optarg, NULL, 10); break;
		case 1007:  job.timeout_ms = strtoull(optarg, NULL, 10); break;
		case 1008:
			if (strcmp(optarg, "none") == 0) {
				job.network_mode = JOBD_NETWORK_NONE;
			} else if (strcmp(optarg, "brokered") == 0) {
				job.network_mode = JOBD_NETWORK_BROKERED;
			} else {
				fprintf(stderr,
				        "--network expects 'none' or 'brokered'\n");
				return 1;
			}
			break;
		case 1012:
			if (job.allow_net_count >= JOBD_MAX_ALLOW_NET) {
				fprintf(stderr, "too many --allow-net options (max %u)\n",
				        JOBD_MAX_ALLOW_NET);
				return 1;
			}
			if (job_allow_net_validate(optarg, err, sizeof(err)) != 0) {
				fprintf(stderr, "%s\n", err);
				return 1;
			}
			if (copy_field(job.allow_net[job.allow_net_count++],
			               JOBD_MAX_ALLOW_LEN, optarg, "--allow-net") != 0)
				return 1;

			job.network_mode = JOBD_NETWORK_BROKERED;
			break;
		case 1009:
			if (strcmp(optarg, "observe") == 0)
				job.fanotify_mode = JOBD_FANOTIFY_OBSERVE;
			else if (strcmp(optarg, "deny") == 0)
				job.fanotify_mode = JOBD_FANOTIFY_DENY;
			else if (strcmp(optarg, "off") == 0)
				job.fanotify_mode = JOBD_FANOTIFY_OFF;
			else {
				fprintf(stderr,
				        "--fanotify expects observe, deny or off\n");
				return 1;
			}
			break;
		case 1010: {
			if (job.memfd_input_count >= JOBD_MAX_MEMFD_INPUT) {
				fprintf(stderr, "too many --memfd-input options (max %u)\n",
				        JOBD_MAX_MEMFD_INPUT);
				return 1;
			}
			char *eq = strchr(optarg, '=');
			if (!eq) {
				fprintf(stderr, "--memfd-input expects NAME=PATH\n");
				return 1;
			}
			*eq = '\0';
			uint32_t i = job.memfd_input_count;
			if (copy_field(job.memfd_inputs[i].name, JOBD_MAX_PATH_LEN,
			               optarg, "--memfd-input name") != 0 ||
			    copy_field(job.memfd_inputs[i].path, JOBD_MAX_PATH_LEN,
			               eq + 1, "--memfd-input path") != 0)
				return 1;
			job.memfd_input_count++;
			break;
		}
		case 1011:  job.iouring_enabled = 1; break;
		case 'n':   dry_run = 1; break;
		case 'e':
			if (job_add_env(&job, optarg, err, sizeof(err)) != 0) {
				fprintf(stderr, "%s\n", err);
				return 1;
			}
			break;
		default:
			return 1;
		}
	}

	if (!job_id) {
		fprintf(stderr, "--id is required\n");
		return 1;
	}
	if (copy_field(job.id, sizeof(job.id), job_id, "--id") != 0)
		return 1;
	if (job_id_validate(job.id, err, sizeof(err)) != 0) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	if (optind >= argc) {
		fprintf(stderr, "missing command (put -- before the command)\n");
		return 1;
	}

	job.dry_run = (uint8_t)dry_run;

	for (int i = optind; i < argc; i++) {
		if (job_add_arg(&job, argv[i], err, sizeof(err)) != 0) {
			fprintf(stderr, "%s\n", err);
			return 1;
		}
	}

	if (job_validate(&job, err, sizeof(err)) != 0) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	uint8_t *payload = malloc(JOBD_MAX_PAYLOAD);
	if (!payload) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	size_t len = 0;
	if (jobd_encode_run_request(&job, payload, JOBD_MAX_PAYLOAD, &len,
	                              err, sizeof(err)) != 0) {
		fprintf(stderr, "%s\n", err);
		free(payload);
		return 1;
	}

	int rc = send_request(JOBD_MSG_RUN, payload, (uint32_t)len);
	free(payload);
	return rc == 0 ? 0 : 1;
}

static int cmd_job(const char *name, uint16_t type, int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "usage: jobctl %s JOB\n", name);
		return 1;
	}

	char err[256];
	if (job_id_validate(argv[1], err, sizeof(err)) != 0) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}

	return send_request(type, (const uint8_t *)argv[1],
	                    (uint32_t)strlen(argv[1])) == 0 ? 0 : 1;
}

static void usage(const char *prog)
{
	fprintf(stderr,
	  "usage: %s <subcommand> [args]\n"
	  "\n"
	  "subcommands:\n"
	  "  run [options] -- COMMAND [ARGS...]   launch a job\n"
	  "  inspect JOB                          show job status\n"
	  "  wait JOB                             block until the job finishes\n"
	  "  logs JOB                             show job output and alerts\n"
	  "  kill JOB                             kill the job cgroup\n"
	  "  list                                 list known jobs\n"
	  "  cleanup JOB                          remove the job's runtime state\n"
	  "  doctor                               check the host and components\n"
	  "\n"
	  "run options:\n"
	  "  --id ID                  job identifier ([A-Za-z0-9_-], 1..64)\n"
	  "  --layer NAME             overlay layer (repeatable)\n"
	  "  --ro PATH                read-only path (repeatable)\n"
	  "  --rw PATH                read-write path (repeatable)\n"
	  "  --canary PATH            fanotify canary path (repeatable)\n"
	  "  --memory-max BYTES       memory limit\n"
	  "  --memory-high BYTES      memory throttling threshold\n"
	  "  --swap-max BYTES         swap limit\n"
	  "  --cpu-max QUOTA/PERIOD   CPU limit, e.g. 100000/100000\n"
	  "  --cpu-weight N           CPU weight\n"
	  "  --pids-max N             maximum number of processes\n"
	  "  --io-weight N            I/O weight\n"
	  "  --timeout-ms N           kill the job after N milliseconds\n"
	  "  --network none|brokered  network mode\n"
	  "  --allow-net HOST:PORT    permitted destination (repeatable, implies\n"
	  "                           --network brokered)\n"
	  "  --fanotify observe|deny|off\n"
	  "  --memfd-input NAME=PATH  sealed memfd input (repeatable)\n"
	  "  --iouring                enable the bounded I/O service\n"
	  "  --env KEY=VALUE          environment entry (repeatable)\n"
	  "  --dry-run                print the plan without executing\n"
	  "\n"
	  "environment:\n"
	  "  JOBD_SOCKET            control socket (default %s)\n",
	  prog, socket_path());
}

int main(int argc, char *argv[])
{
	jobd_config_init();

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	const char *cmd = argv[1];

	if (strcmp(cmd, "run") == 0)
		return cmd_run(argc - 1, argv + 1);
	if (strcmp(cmd, "inspect") == 0)
		return cmd_job("inspect", JOBD_MSG_INSPECT, argc - 1, argv + 1);
	if (strcmp(cmd, "wait") == 0)
		return cmd_job("wait", JOBD_MSG_WAIT, argc - 1, argv + 1);
	if (strcmp(cmd, "logs") == 0)
		return cmd_job("logs", JOBD_MSG_LOGS, argc - 1, argv + 1);
	if (strcmp(cmd, "kill") == 0)
		return cmd_job("kill", JOBD_MSG_KILL, argc - 1, argv + 1);
	if (strcmp(cmd, "cleanup") == 0)
		return cmd_job("cleanup", JOBD_MSG_CLEANUP, argc - 1, argv + 1);
	if (strcmp(cmd, "list") == 0)
		return send_request(JOBD_MSG_LIST, NULL, 0) == 0 ? 0 : 1;
	if (strcmp(cmd, "doctor") == 0)
		return send_request(JOBD_MSG_DOCTOR, NULL, 0) == 0 ? 0 : 1;

	if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
		usage(argv[0]);
		return 0;
	}

	fprintf(stderr, "unknown subcommand: %s\n", cmd);
	usage(argv[0]);
	return 1;
}
