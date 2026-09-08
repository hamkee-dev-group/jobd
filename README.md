# jobd — Job Runtime Supervisor

Run a command under real Linux confinement — namespaces, Landlock, seccomp,
cgroup v2 and an overlay filesystem — in about 30 milliseconds.

jobd is for workloads you do not fully trust: CI steps, third-party build
scripts, plugins, customer-submitted code, batch jobs. It gives each one a
private filesystem, an explicit resource budget, no network unless you grant
it, and a per-job record of what it tried to do. It is smaller and roughly
twenty times faster to start than a container, and unlike `bwrap` or `nsjail`
it is a supervising daemon: jobs have identity, state, logs and cleanup.

It fails closed. If any part of the confinement cannot be established, the
job does not run.

jobd is the orchestration layer only. Each isolation primitive is enforced by
the component that owns it — jobd validates the request, prepares the
filesystem, compiles the policy, starts what the job asked for, launches the
workload through the chain, supervises it and cleans up.

## Requirements

- Linux with **cgroup v2**, **seccomp** and **Landlock** (kernel 5.13 or
  newer). Developed and tested on 6.12.
- **Root.** Namespaces, cgroups and fanotify all need it.
- Five sibling components, all required: `sandbox`, `landlockd`, `cgroupd`
  (for `cgroupctl`), `overlayd`, and jobd's own `job-init`.
- Four more, used only when a job asks for them: `fanotifyd`, `memfdbus`,
  `iouringd`, and jobd's own `job-netd`.

`jobctl doctor` checks all of this and reports what is missing.

## Build

```sh
make
```

Produces `build/jobd`, `build/jobctl`, `build/job-init` and `build/job-netd`.

```sh
make test       # 66 unit tests
make sanitize   # unit tests under ASan + UBSan
make lint       # cppcheck
sudo tests/integration.sh   # 64 real-kernel end-to-end tests
```

The integration suite needs the sibling components. If they are not
installed, point it at the build trees:

```sh
sudo JOBD_COMPONENT_PATH=/src/cgroupd/build:/src/sandbox:/src/landlock/build/src:/src/fanotifyd:/src/memfdbus/build:/src/iouringd/build/bin:/src/overlayd \
     tests/integration.sh
```

## Quick start

Start the daemon:

```sh
sudo jobd --config /etc/jobd/jobd.conf
```

Check the host is capable and every component was found:

```sh
jobctl doctor
```

Run something:

```sh
jobctl run --id demo --pids-max 64 --memory-max 2147483648 \
    --timeout-ms 60000 --rw /workspace \
    -- /usr/bin/python3 /workspace/job.py
jobctl wait demo
jobctl logs demo
```

`run` returns as soon as the workload is launched; `wait` blocks until it
finishes. The daemon stays responsive throughout and jobs run concurrently.

Add `--dry-run` to any `run` to print the exact plan — resolved component
paths, the compiled policy, the cgroup limits and the full argv chain —
without executing anything.

A job using more of the chain:

```sh
jobctl run --id demo2 --pids-max 64 \
    --layer python-base \
    --memfd-input model=/srv/models/model.bin \
    --fanotify deny --canary /workspace/.credentials \
    --allow-net api.example.com:443 \
    -- /usr/bin/python3 /workspace/job.py
```

That job gets a `python-base` overlay layer, a sealed read-only copy of a
model file, egress restricted to one host and port, and a honeypot file that
kills the job if the workload touches it.

## Commands

| Command | What it does |
|---------|--------------|
| `run [options] -- CMD` | Launch a job. Returns once the workload has started. |
| `inspect JOB` | Show a job's state, exit code and exit reason. |
| `wait JOB` | Block until the job reaches a terminal state. |
| `logs JOB` | Show the job's output and any monitoring alerts. |
| `list` | List known jobs and their states. |
| `kill JOB` | Kill the job's cgroup, and so every process in it. |
| `cleanup JOB` | Unmount the overlay and remove the job's runtime state. |
| `doctor` | Check kernel features, locate every component, print the effective configuration. Run this first when something does not work. |

`jobctl run --help` lists every option. The main ones:

| Option | Meaning |
|--------|---------|
| `--id ID` | Job identifier, `[A-Za-z0-9_-]`, 1–64 bytes |
| `--layer NAME` | Overlay layer to stack into the job root (repeatable) |
| `--ro PATH` / `--rw PATH` | Bind a host path read-only or read-write (repeatable) |
| `--memory-max`, `--pids-max`, `--cpu-max`, `--io-weight` | cgroup limits |
| `--timeout-ms N` | Kill the job after N milliseconds |
| `--network none\|brokered` | Network mode; `none` is the default |
| `--allow-net HOST:PORT` | Permit one destination (repeatable, implies `brokered`) |
| `--fanotify observe\|deny\|off` | Filesystem monitoring mode |
| `--canary PATH` | Honeypot path; touching it triggers the policy reaction |
| `--memfd-input NAME=PATH` | Publish a host file as a sealed, immutable memfd |
| `--iouring` | Enable the bounded async I/O service |
| `--env KEY=VALUE` | Environment entry (repeatable) |
| `--dry-run` | Print the plan without executing it |

## Install

```sh
sudo make install
```

Installs to `$(PREFIX)/bin` (default `/usr/local/bin`), the helper to
`$(PREFIX)/libexec/jobd`, and an example configuration to `/etc/jobd/jobd.conf`
if none exists.

## Configuration

See [examples/jobd.conf](examples/jobd.conf) for every key. The three things
worth knowing:

### Finding the components

**No component path is compiled in.** jobd resolves each sibling program at
run time, in this order:

1. `--component NAME=PATH` on the command line
2. an entry in the configuration file (default `/etc/jobd/jobd.conf`)
3. the environment variable `JOBD_<NAME>`, e.g. `JOBD_CGROUPCTL`
4. a search path: `JOBD_COMPONENT_PATH` if set, otherwise the directory
   containing the running `jobd` binary, then `$(PREFIX)/libexec/jobd`,
   `$(PREFIX)/bin`, `$(PREFIX)/sbin`, `/usr/local/bin`, `/usr/local/sbin`,
   `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`

Step 4 finds the siblings where their own `make install` puts them, so an
installed system usually needs no configuration at all. It also finds
`job-init` next to `jobd`, so an uninstalled build tree works as-is:

```sh
sudo JOBD_COMPONENT_PATH=/src/cgroupd/build:/src/sandbox:/src/landlock/build/src \
     ./build/jobd
```

### Access control

jobd runs workloads as root, so its control socket is an authorisation
boundary. Every connection is checked with `SO_PEERCRED` against an allowlist;
**the default is root only.** To grant a group:

```
allow_gid = 4242
```

The socket's permissions follow the allowlist, but the peer check is the real
gate — widening the socket mode by hand does not grant access.

### Optional components

fanotifyd, memfdbus, iouringd and the network broker start only when a job
asks for them. A job that requests none of them runs with none of their code:
the process is never spawned and no socket for it appears in the job root.

That is a per-job choice, so normally the client decides it. These keys let
the operator decide instead, and refuse the request outright:

```
allow_iouring  = no
allow_network  = no
allow_fanotify = no
allow_memfd    = no
```

All default to `yes`. A job asking for a forbidden component is rejected
before any setup runs — a dry run included — so a locked-down daemon can say
the component is unreachable rather than merely unused. `jobctl doctor` prints
the effective policy.

This is what makes the trusted computing base configurable. With all four
refused, the only code that can run is `jobd`, `sandbox`, `landlockd`,
`cgroupd` and `overlayd`. io_uring in particular is something most hardened
runtimes remove entirely, and this is how to remove it here.

## How it works

```
jobctl (CLI)
   |  Unix socket, JBD1 framed protocol, SO_PEERCRED authorisation
   v
jobd (validation, policy compiler, state machine, event loop)
   |
   +--> overlayd    filesystem layers
   +--> fanotifyd   host-side monitoring and canaries
   +--> memfdbus    sealed memfd object bus
   +--> iouringd    bounded async I/O
   +--> cgroupd     resource limits and lifecycle
   |
   +--> job-init    network/IPC/mount namespaces, FD sanitisation
            |
            +--> sandbox
                     |
                     +--> landlockd  Landlock + seccomp
                              |
                              +--> the workload
```

Launching a job runs these steps in order. Any failure in steps 1–9 unwinds
the rollback stack, and the workload never runs.

```
0. validate the request (job ID, argv, paths, limits)
1. preflight: root, CAP_SYS_ADMIN, namespaces, Landlock, seccomp, components
2. create the job directory tree
3. overlayd mounts the job root (workspace over the requested layers)
4. stage the rootfs: the target binary, its ELF dependencies, device nodes,
   and any client binaries the requested features need
5. compile the landlockd policy (Landlock rules + seccomp deny list)
6. start fanotifyd, if monitoring was requested
7. start memfdbus and publish the sealed inputs, if any
8. start iouringd, if requested
9. start job-netd, if networking is brokered
10. cgroupctl run -> job-init -> sandbox -> [relay] -> landlockd -> workload
11. supervise: pidfd for completion, timerfd for the deadline,
    inotify on the alert stream for policy reactions
12. on exit: stop what was started, remove the cgroup, record the result
13. on `cleanup`: unmount the overlay and remove the job tree
```

### What the job root contains

Only what the job needs: the target binary, the shared libraries its ELF
dynamic section names, a minimal `/dev`, and the client binaries for the
features requested. Anything else — a shell's usual toolbox, an interpreter's
standard library — belongs in an overlay layer:

```sh
overlayd --root /var/lib/jobd/overlay layer create python-base
# populate the layer, then
jobctl run --id j1 --layer python-base -- /usr/bin/python3 /workspace/job.py
```

## Security model

Both the control socket and the workload are treated as untrusted input.

**Against a hostile client:**

- Requests are decoded with explicit bounds. Every count is checked against
  its limit before any element is copied, and every string carries a length
  that must fit its destination.
- Job IDs are restricted to `[A-Za-z0-9_-]`, 1–64 bytes, and validated on
  every command before they reach a filesystem path or a child's argv.
- Client paths must be absolute and free of `..` before they are pasted into
  the job root or the generated policy.
- Generated policy escapes every interpolated value, so a path cannot inject
  extra rules into the policy that constrains it.
- Untrusted binaries are never executed for inspection. Library dependencies
  come from parsing the ELF dynamic section, not from running `ldd`, which
  would execute the file's own interpreter as root.

**Against a hostile workload:**

- It sees no host filesystem outside its own root, and no network at all
  unless `brokered` was requested — in which case it reaches only the
  allowlisted destinations, and cannot bypass the proxy.
- It cannot escape its resource budget by forking; accounting is the cgroup's,
  not the process's. Killing a job kills every descendant.
- It cannot reach another job's runtime state. Each job gets its own
  directory tree and its own sidecar instances.
- Sealed memfd inputs are immutable — it can read them and cannot alter them.
- Its output goes to files captured by cgroupd, never into a supervisor
  buffer.
- It does not inherit the environment. It gets a fixed minimal set plus
  whatever the client passed with `--env`.

**Structurally:** no shell is used anywhere in the privileged path — every
child is spawned with an argv array. Cleanup is idempotent, and a daemon
restart reclaims jobs left behind rather than leaving a workload running
unmonitored.

## Limitations

1. **Root is required**, and so are Landlock and seccomp. If the kernel lacks
   either, preflight refuses the job rather than running it unconfined.
2. **overlayd is required, not optional.** The job root must be a real mount.
   The runtime directory normally lives under `/run`, which is mounted
   `noexec` and `nodev`, so a plain directory there could neither execute the
   staged binary nor open a device node.
3. **Confinement is kernel-enforced.** Namespaces, Landlock and seccomp are
   the boundary, so a kernel privilege escalation defeats them. For a
   maximally hostile workload, run jobd inside a microVM and let it provide
   per-job policy and forensics within that boundary.
4. **`allowlisted` networking is not implemented.** `none` and `brokered`
   are. A veth-and-firewall mode would need `nftables` or `iptables` on the
   host.
5. **No seccomp-notify broker.** Denied syscalls return `EPERM`; there is no
   userspace handler.
6. **The seccomp deny list is limited to names landlockd recognises.**
   `keyctl`, `add_key`, `request_key`, `name_to_handle_at` and
   `kexec_file_load` are not in landlockd's syscall table, and including one
   would make it reject the whole policy.
7. **`--memfd-input` accepts any host path.** There are no administrator-defined
   import roots, so the uid/gid allowlist is the only control over who may ask
   for it.
8. **Job setup runs inline in the event loop.** A `run` request occupies the
   daemon for the length of setup — not the length of the job. Client sockets
   carry a receive timeout so a stalled client cannot wedge the loop.

### fanotify monitoring always uses permission events

Every monitored job passes `--perm`, in `observe` mode as well as `deny`.
This is a requirement, not caution: the job root is an overlay mount, and on
overlayfs a `FAN_MARK_FILESYSTEM` mark is rejected with `EOPNOTSUPP` unless
the group was created for permission events. `--mount` is rejected with
`EINVAL`, and an inode mark starts but reports nothing.

The cost is that every `open` in the sandbox waits for fanotifyd to answer.
Do not drop `--perm` for `observe` mode without re-testing against a real
overlay mount.

Startup requires the child's PID and its complete `INFO` message
`fanotifyd started (pid=...) -- 1 mark(s), canaries=..., burst=...`.
In fanotifyd's `src/daemon.c:daemon_run`, the pidfile follows mark installation,
but this message follows successful policy, mark, and event-loop setup.
jobd checks the reported PID and counts, then confirms the child is still alive.
A component that does not emit this message fails setup within the existing
three-second polling budget. Diagnostics are kept in `logs/fanotifyd.stderr`;
the alert log remains JSONL.

### jobd depends on two sandbox behaviours

`sandbox` must bring loopback up inside the namespace it creates, because
brokered networking binds `127.0.0.1`. It must also not clear the environment
in `--existing-rootfs` mode, because jobd owns the workload environment —
without that, `--env`, `MEMFDBUS_SOCKET`, `IOURINGD_SOCKET` and `ALL_PROXY`
never reach the workload.

## Layout

```
jobd/
├── Makefile
├── examples/jobd.conf
├── include/       jobd.h, jobd_config.h, jobd_buf.h, protocol.h,
│                  job.h, state.h
├── src/
│   ├── jobd.c                daemon, event loop, request handling
│   ├── jobctl.c              CLI client
│   ├── job_init.c            namespaces and FD sanitisation (standalone)
│   ├── job_netd.c            egress broker and relay (standalone)
│   ├── config.c              component and path resolution
│   ├── buf.c                 bounded output buffer
│   ├── protocol.c            framing and the byte codec
│   ├── request.c             run-request encode/decode
│   ├── job.c                 job model and validation
│   ├── policy.c              dry-run plan
│   ├── execute.c             launch pipeline and rollback
│   ├── elfdeps.c             ELF dependency resolution
│   ├── spawn.c               child process helper
│   ├── monitor.c             policy reaction, alert scanning
│   ├── cleanup.c             reaping and idempotent cleanup
│   ├── state.c               job table and persistence
│   ├── doctor.c              host and component checks
│   ├── preflight.c           per-job preconditions
│   └── adapter_*.c           one adapter per component
├── tests/unit/               66 unit tests
└── tests/integration.sh      64 end-to-end tests (root)
```
