#!/bin/bash
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

JOBD="${JOBD:-$ROOT/build/jobd}"
JOBCTL="${JOBCTL:-$ROOT/build/jobctl}"

WORK="${WORK:-/tmp/jobd-integration-$$}"
SOCK="$WORK/jobd.sock"
CONF="$WORK/jobd.conf"
LOG="$WORK/jobd.log"

PASS=0
FAIL=0

if [ "$(id -u)" != "0" ]; then
	echo "these tests need root (namespaces, cgroups, fanotify)" >&2
	exit 77
fi

for bin in "$JOBD" "$JOBCTL"; do
	if [ ! -x "$bin" ]; then
		echo "missing $bin — run make first" >&2
		exit 1
	fi
done

ok()   { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

check() {
	local label="$1" expected="$2" actual="$3"
	if [ "$expected" = "$actual" ]; then
		ok "$label"
	else
		bad "$label (expected '$expected', got '$actual')"
	fi
}

contains() {
	local label="$1" needle="$2" haystack="$3"
	if printf '%s' "$haystack" | grep -qF -- "$needle"; then
		ok "$label"
	else
		bad "$label (missing '$needle')"
		printf '    output: %s\n' "$haystack" | head -5
	fi
}

not_contains() {
	local label="$1" needle="$2" haystack="$3"
	if printf '%s' "$haystack" | grep -qF -- "$needle"; then
		bad "$label (unexpectedly found '$needle')"
	else
		ok "$label"
	fi
}

ctl() { JOBD_SOCKET="$SOCK" "$JOBCTL" "$@" 2>&1; }

component() {
	ctl doctor | sed -n "s/^  $1  *PASS  //p" | head -1
}

field() {  # field <job> <key>
	ctl inspect "$1" | sed -n "s/^$2: //p"
}

cleanup() {
	pkill -x jobd 2>/dev/null
	pkill -x cgroupd 2>/dev/null
	sleep 0.3
	mount | awk -v w="$WORK" '$3 ~ w {print $3}' | while read -r m; do
		umount -l "$m" 2>/dev/null
	done
	rm -rf "$WORK"
	rmdir /sys/fs/cgroup/jobd-itest.slice/* 2>/dev/null
	rmdir /sys/fs/cgroup/jobd-itest.slice 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$WORK/run" "$WORK/state"
cat > "$CONF" <<EOF
runtime_dir = $WORK/run
state_dir = $WORK/state
socket = $SOCK
cgroup_sock = $WORK/cgroupd.sock
cgroup_root = /sys/fs/cgroup/jobd-itest.slice
cgroup_log_dir = $WORK/cgroup-logs
allow_uid = 0
EOF

echo "=== starting jobd ==="
"$JOBD" --config "$CONF" > "$LOG" 2>&1 &
for _ in $(seq 1 40); do
	[ -S "$SOCK" ] && break
	sleep 0.1
done
if [ ! -S "$SOCK" ]; then
	echo "jobd did not start:" >&2
	cat "$LOG" >&2
	exit 1
fi

echo
echo "=== Test 0 — doctor ==="
out="$(ctl doctor)"
contains "doctor reports kernel features" "cgroup v2" "$out"
contains "doctor reports the search path" "search path:" "$out"
contains "doctor reports the configured runtime dir" "$WORK/run" "$out"

missing=0
for c in cgroupctl sandbox landlockd job-init; do
	if printf '%s' "$out" | grep -qE "^  $c +FAIL"; then
		echo "  SKIP: $c not found; set JOBD_COMPONENT_PATH" >&2
		missing=1
	fi
done
if [ "$missing" = "1" ]; then
	echo
	echo "required components missing — skipping execution tests"
	echo "PASS=$PASS FAIL=$FAIL"
	[ "$FAIL" = "0" ] || exit 1
	exit 77
fi

echo
echo "=== Test 1 — dry run describes the real paths ==="
out="$(ctl run --id dry1 --pids-max 32 --dry-run -- /bin/echo hello)"
contains "plan uses the configured runtime dir" "$WORK/run/dry1/root" "$out"
contains "plan lists the resolved cgroupctl" "cgroupctl" "$out"
contains "plan denies ptrace" "deny_syscall             = ptrace" "$out"
not_contains "a dry run creates no job directory" "dry1" \
	"$(ls "$WORK/run" 2>/dev/null)"

echo
echo "=== Test 2 — basic success ==="
ctl run --id basic1 --pids-max 32 --timeout-ms 30000 -- /bin/echo hi >/dev/null
ctl wait basic1 >/dev/null
check "exit code is 0" "0" "$(field basic1 exit_code)"
check "state is EXITED" "EXITED" "$(field basic1 state)"
contains "workload output is captured" "hi" "$(ctl logs basic1)"

echo
echo "=== Test 3 — exit codes propagate ==="
ctl run --id exit7 --pids-max 32 --timeout-ms 30000 -- /bin/sh -c "exit 7" >/dev/null
ctl wait exit7 >/dev/null
check "exit code is 7" "7" "$(field exit7 exit_code)"

echo
echo "=== Test 4 — arguments containing spaces stay whole ==="
ctl run --id spaces1 --pids-max 32 --timeout-ms 30000 -- \
	/bin/echo "one two three" >/dev/null
ctl wait spaces1 >/dev/null
contains "argument arrives as one word" "one two three" "$(ctl logs spaces1)"

echo
echo "=== Test 5 — timeout kills the job ==="
start=$(date +%s)
ctl run --id tmo1 --pids-max 32 --timeout-ms 3000 -- \
	/bin/sh -c "while true; do :; done" >/dev/null
ctl wait tmo1 >/dev/null
elapsed=$(( $(date +%s) - start ))
check "reason is TIMEOUT" "TIMEOUT" "$(field tmo1 exit_reason)"
if [ "$elapsed" -ge 2 ] && [ "$elapsed" -le 15 ]; then
	ok "timeout fired near the deadline (${elapsed}s)"
else
	bad "timeout timing looks wrong (${elapsed}s)"
fi

echo
echo "=== Test 6 — the daemon stays responsive while a job runs ==="
ctl run --id long1 --pids-max 32 --timeout-ms 60000 -- \
	/bin/sh -c "while true; do :; done" >/dev/null
contains "list responds during a running job" "long1" "$(ctl list)"
contains "doctor responds during a running job" "jobd doctor" "$(ctl doctor)"
ctl kill long1 >/dev/null
ctl wait long1 >/dev/null
check "killed job is KILLED" "KILLED" "$(field long1 state)"

echo
echo "=== Test 7 — concurrent jobs ==="
for i in 1 2 3; do
	ctl run --id "conc$i" --pids-max 32 --timeout-ms 60000 -- \
		/bin/sh -c "while true; do :; done" >/dev/null
done
running="$(ctl list | grep -c RUNNING)"
check "three jobs run at once" "3" "$running"
for i in 1 2 3; do ctl kill "conc$i" >/dev/null; done
for i in 1 2 3; do ctl wait "conc$i" >/dev/null; done

echo
echo "=== Test 8 — validation rejects hostile input ==="
out="$(ctl run --id "../escape" -- /bin/true)"
contains "traversal in a job ID is refused" "invalid job ID" "$out"
out="$(ctl inspect "../../etc/passwd")"
contains "traversal in inspect is refused" "invalid job ID" "$out"
out="$(ctl run --id relcmd -- true)"
contains "a relative command is refused" "absolute path" "$out"
out="$(ctl run --id badpath --rw "../../etc" -- /bin/true)"
contains "a traversal path is refused" "absolute" "$out"

echo
echo "=== Test 9 — no host network ==="
ctl run --id net1 --pids-max 32 --network none --timeout-ms 30000 -- \
	/bin/sh -c "ls /sys/class/net" >/dev/null
ctl wait net1 >/dev/null
out="$(ctl logs net1)"
not_contains "no host interfaces are visible" "eth0" "$out"

echo
echo "=== Test 10 — PID limit is enforced ==="
ctl run --id pids1 --pids-max 8 --timeout-ms 20000 -- \
	/bin/sh -c "i=0; while [ \$i -lt 200 ]; do /bin/sh -c 'sleep 5' & i=\$((i+1)); done; wait" \
	>/dev/null
ctl wait pids1 >/dev/null
ok "pid-limited job terminated (state $(field pids1 state))"

echo
echo "=== Test 11 — overlayd provides the job root ==="
ctl run --id ov1 --pids-max 32 --timeout-ms 30000 -- /bin/echo ok >/dev/null
if findmnt -no FSTYPE "$WORK/run/ov1/root" 2>/dev/null | grep -q overlay; then
	ok "the job root is an overlay mount"
else
	bad "the job root is not an overlay mount"
fi
ctl wait ov1 >/dev/null
check "a job on the overlay root runs" "0" "$(field ov1 exit_code)"
if [ -c "$WORK/run/ov1/root/dev/null" ]; then
	ok "device nodes exist in the job root"
else
	bad "no device nodes in the job root"
fi
ctl run --id ov2 --pids-max 32 --timeout-ms 30000 -- \
	/bin/sh -c "echo redirect > /dev/null && echo devok" >/dev/null
ctl wait ov2 >/dev/null
contains "shell redirection to /dev/null works" "devok" "$(ctl logs ov2)"

echo
echo "=== Test 12 — overlay layers are immutable and per job ==="
STORE="$WORK/state/overlay"
OVERLAYD="$(component overlayd)"
"$OVERLAYD" --root "$STORE" layer create shared-base >/dev/null 2>&1
LAYER="$("$OVERLAYD" --root "$STORE" layer path shared-base 2>/dev/null)"
if [ -n "$LAYER" ]; then
	mkdir -p "$LAYER/workspace"
	echo "from-layer" > "$LAYER/workspace/layer-file"

	ctl run --id lay1 --layer shared-base --pids-max 32 --timeout-ms 30000 -- \
		/bin/sh -c "read l < /workspace/layer-file; echo \$l; echo overwritten > /workspace/layer-file" \
		>/dev/null
	ctl wait lay1 >/dev/null
	contains "a job sees the layer content" "from-layer" "$(ctl logs lay1)"

	if grep -q "from-layer" "$LAYER/workspace/layer-file"; then
		ok "the layer is unchanged after the job wrote to it"
	else
		bad "the job modified the shared layer"
	fi

	ctl run --id lay2 --layer shared-base --pids-max 32 --timeout-ms 30000 -- \
		/bin/sh -c "read l < /workspace/layer-file; echo \$l" >/dev/null
	ctl wait lay2 >/dev/null
	contains "a second job sees the original content" "from-layer" "$(ctl logs lay2)"
	not_contains "one job's write is invisible to another" "overwritten" \
		"$(ctl logs lay2)"
else
	bad "could not create a test layer"
fi

out="$(ctl run --id badlayer --layer does-not-exist --dry-run -- /bin/true)"
ctl run --id badlayer2 --layer does-not-exist --pids-max 32 -- /bin/true >/dev/null 2>&1
contains "an unknown layer is refused" "does not exist" \
	"$(ctl run --id badlayer3 --layer does-not-exist --pids-max 32 -- /bin/true 2>&1)"

echo
echo "=== Test 13 — memfdbus sealed input ==="
echo "sealed-payload-contents" > "$WORK/model.bin"
ctl run --id mb1 --pids-max 32 --timeout-ms 30000 \
	--memfd-input model="$WORK/model.bin" -- \
	/bin/sh -c "/usr/bin/memfdbus get --name model /workspace/got.bin --job-id mb1 --socket /run/jobd/memfdbus.sock >/dev/null && read l < /workspace/got.bin && echo \$l" \
	>/dev/null
ctl wait mb1 >/dev/null
contains "the job retrieves its sealed input" "sealed-payload-contents" \
	"$(ctl logs mb1)"
check "the memfd job succeeds" "0" "$(field mb1 exit_code)"

ctl run --id mb2 --pids-max 32 --timeout-ms 30000 \
	--memfd-input model="$WORK/model.bin" -- \
	/bin/sh -c "/usr/bin/memfdbus get --name model /workspace/got.bin --job-id someone-else --socket /run/jobd/memfdbus.sock; echo rc=\$?" \
	>/dev/null
ctl wait mb2 >/dev/null
contains "another job's ID is refused by the broker" "rc=1" "$(ctl logs mb2)"

echo
echo "=== Test 14 — fanotifyd canary detection and reaction ==="
ctl run --id fa1 --pids-max 32 --timeout-ms 30000 \
	--fanotify deny --canary /workspace/secret.txt -- \
	/bin/sh -c "echo data > /workspace/secret.txt; echo wrote-rc=\$?; while true; do :; done" \
	>/dev/null
sleep 4
contains "the canary write is denied" "wrote-rc=2" "$(ctl logs fa1)"
if [ -s "$WORK/run/fa1/logs/fanotifyd.jsonl" ] && \
   grep -q '"type":"alert"' "$WORK/run/fa1/logs/fanotifyd.jsonl"; then
	ok "a canary alert was recorded"
else
	bad "no canary alert was recorded"
fi
ctl wait fa1 >/dev/null
check "the job is killed by policy" "POLICY_KILL" "$(field fa1 exit_reason)"

echo
echo "=== Test 15 — iouringd is started and reachable ==="
ctl run --id io1 --pids-max 32 --timeout-ms 30000 --iouring -- \
	/bin/sh -c "ls /run/jobd/ 2>/dev/null; while true; do :; done" >/dev/null
sleep 3
if [ -S "$WORK/run/io1/root/run/jobd/iouringd.sock" ]; then
	ok "the iouringd socket exists in the job root"
else
	bad "no iouringd socket in the job root"
fi
ctl kill io1 >/dev/null
ctl wait io1 >/dev/null

echo
echo "=== Test 16 — the workload environment is what jobd set ==="
ctl run --id env1 --pids-max 32 --timeout-ms 30000 --env MY_SETTING=hello -- \
	/bin/sh -c "echo \$MY_SETTING; echo job=\$JOBD_JOB_ID" >/dev/null
ctl wait env1 >/dev/null
out="$(ctl logs env1)"
contains "a --env entry reaches the workload" "hello" "$out"
contains "JOBD_JOB_ID reaches the workload" "job=env1" "$out"

echo
echo "=== Test 16b — brokered networking ==="
if [ ! -x "$(command -v python3 2>/dev/null)" ] || [ ! -x /usr/bin/curl ]; then
	echo "  SKIP: python3 and curl are needed for the network tests"
else
	python3 -m http.server 18099 --bind 127.0.0.1 \
		--directory "$WORK" >/dev/null 2>&1 &
	HTTPD=$!
	echo "brokered-ok" > "$WORK/probe.txt"
	sleep 1

	ctl run --id netok --pids-max 32 --timeout-ms 30000 \
		--allow-net 127.0.0.1:18099 -- \
		/usr/bin/curl -sS --max-time 8 http://127.0.0.1:18099/probe.txt >/dev/null
	ctl wait netok >/dev/null
	contains "an allowed destination is reachable" "brokered-ok" "$(ctl logs netok)"
	check "the allowed job succeeds" "0" "$(field netok exit_code)"

	ctl run --id netport --pids-max 32 --timeout-ms 30000 \
		--allow-net 127.0.0.1:18099 -- \
		/usr/bin/curl -sS --max-time 8 http://127.0.0.1:18098/ >/dev/null
	ctl wait netport >/dev/null
	not_contains "a different port is refused" "brokered-ok" "$(ctl logs netport)"
	if [ "$(field netport exit_code)" = "0" ]; then
		bad "a non-allowlisted port succeeded"
	else
		ok "a non-allowlisted port is refused"
	fi

	ctl run --id nethost --pids-max 32 --timeout-ms 30000 \
		--allow-net 127.0.0.1:18099 -- \
		/usr/bin/curl -sS --max-time 8 http://example.com/ >/dev/null
	ctl wait nethost >/dev/null
	if [ "$(field nethost exit_code)" = "0" ]; then
		bad "a non-allowlisted host succeeded"
	else
		ok "a non-allowlisted host is refused"
	fi

	ctl run --id netbyp --pids-max 32 --timeout-ms 30000 \
		--allow-net 127.0.0.1:18099 -- \
		/usr/bin/curl -sS --noproxy "*" --max-time 6 \
		http://127.0.0.1:18099/probe.txt >/dev/null
	ctl wait netbyp >/dev/null
	not_contains "the proxy cannot be bypassed" "brokered-ok" "$(ctl logs netbyp)"

	contains "--allow-net without a port is refused" "HOST:PORT" \
		"$(ctl run --id badnet --allow-net "example.com" -- /bin/true 2>&1)"
	contains "brokered mode needs a destination" "requires at least one" \
		"$(ctl run --id badnet2 --network brokered -- /bin/true 2>&1)"

	kill $HTTPD 2>/dev/null
fi

echo
echo "=== Test 17 — cleanup removes the job tree ==="
ctl cleanup basic1 >/dev/null
if [ -d "$WORK/run/basic1" ]; then
	bad "cleanup left $WORK/run/basic1 behind"
else
	ok "cleanup removed the job directory"
fi
if mount | grep -q "$WORK/run/basic1/root"; then
	bad "cleanup left the overlay mounted"
else
	ok "cleanup unmounted the overlay"
fi
not_contains "cleaned job leaves the table" "basic1" "$(ctl list)"
contains "cleanup is idempotent" "no such job" "$(ctl cleanup basic1)"

echo
echo "=== Test 18 — restart reclaims stale jobs ==="
ctl run --id stale1 --pids-max 32 --timeout-ms 60000 -- \
	/bin/sh -c "while true; do :; done" >/dev/null
pkill -9 -x jobd
sleep 0.5
"$JOBD" --config "$CONF" > "$WORK/jobd2.log" 2>&1 &
for _ in $(seq 1 40); do
	[ -S "$SOCK" ] && break
	sleep 0.1
done
contains "restart reports the reclaim" "reclaiming stale job stale1" \
	"$(cat "$WORK/jobd2.log")"
sleep 1
if [ -d "$WORK/run/stale1" ]; then
	bad "stale job directory survived the restart"
else
	ok "stale job directory was removed"
fi

echo
echo "=== Test 19 — the operator can forbid optional components ==="
pkill -9 -x jobd
sleep 0.5
LOCKED="$WORK/locked.conf"
cp "$CONF" "$LOCKED"
cat >> "$LOCKED" <<EOF
allow_iouring = no
allow_network = no
allow_fanotify = no
allow_memfd = no
EOF
"$JOBD" --config "$LOCKED" > "$WORK/jobd3.log" 2>&1 &
for _ in $(seq 1 40); do
	[ -S "$SOCK" ] && break
	sleep 0.1
done

contains "doctor reports the locked policy" "allow_iouring          no" \
	"$(ctl doctor)"
contains "io_uring is refused" "io_uring is disabled by the daemon" \
	"$(ctl run --id gate1 --pids-max 32 --iouring -- /bin/true)"
contains "networking is refused" "networking is disabled by the daemon" \
	"$(ctl run --id gate2 --pids-max 32 --network brokered \
		--allow-net example.com:443 -- /bin/true)"
contains "fanotify is refused" "fanotify is disabled by the daemon" \
	"$(ctl run --id gate3 --pids-max 32 --fanotify observe -- /bin/true)"
contains "a dry run is refused too" "io_uring is disabled by the daemon" \
	"$(ctl run --id gate4 --pids-max 32 --iouring --dry-run -- /bin/true)"
not_contains "a refused job leaves no entry" "gate1" "$(ctl list)"

ctl run --id gate5 --pids-max 32 --timeout-ms 30000 -- /bin/echo ok >/dev/null
ctl wait gate5 >/dev/null
check "a job needing nothing optional still runs" "0" "$(field gate5 exit_code)"

pkill -9 -x jobd
sleep 0.5
BADCONF="$WORK/bad.conf"
cp "$CONF" "$BADCONF"
echo "allow_iouring = maybe" >> "$BADCONF"
out="$("$JOBD" --config "$BADCONF" 2>&1)"
contains "an invalid value is rejected at startup" "expected yes or no" "$out"

echo
echo "==================================="
echo "PASS: $PASS   FAIL: $FAIL"
echo "==================================="
[ "$FAIL" = "0" ]
