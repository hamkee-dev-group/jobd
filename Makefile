CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -pedantic -O2 -g
LDFLAGS ?=

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec/jobd
SYSCONFDIR ?= /etc

SRC_DIR   = src
INC_DIR   = include
BUILD_DIR = build

ALL_CFLAGS  = $(CFLAGS) $(EXTRA_CFLAGS) -I$(INC_DIR) \
              -DJOBD_PREFIX=\"$(PREFIX)\" \
              -DJOBD_SYSCONFDIR=\"$(SYSCONFDIR)\"
ALL_LDFLAGS = $(LDFLAGS) $(EXTRA_LDFLAGS)

SRCS = $(SRC_DIR)/buf.c \
       $(SRC_DIR)/config.c \
       $(SRC_DIR)/protocol.c \
       $(SRC_DIR)/request.c \
       $(SRC_DIR)/job.c \
       $(SRC_DIR)/paths.c \
       $(SRC_DIR)/doctor.c \
       $(SRC_DIR)/policy.c \
       $(SRC_DIR)/spawn.c \
       $(SRC_DIR)/elfdeps.c \
       $(SRC_DIR)/execute.c \
       $(SRC_DIR)/adapter_overlayd.c \
       $(SRC_DIR)/adapter_overlay_ws.c \
       $(SRC_DIR)/adapter_sandbox.c \
       $(SRC_DIR)/adapter_landlockd.c \
       $(SRC_DIR)/adapter_cgroupd.c \
       $(SRC_DIR)/adapter_fanotifyd.c \
       $(SRC_DIR)/adapter_memfdbus.c \
       $(SRC_DIR)/adapter_iouringd.c \
       $(SRC_DIR)/adapter_netd.c \
       $(SRC_DIR)/cleanup.c \
       $(SRC_DIR)/state.c \
       $(SRC_DIR)/monitor.c \
       $(SRC_DIR)/preflight.c

COMMON_OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

TESTS = test_protocol test_job test_policy test_adversarial test_state \
        test_buf test_request test_preflight
TEST_BINS = $(TESTS:%=$(BUILD_DIR)/%)

.PHONY: all clean install uninstall test check sanitize lint

all: $(BUILD_DIR)/jobd $(BUILD_DIR)/jobctl $(BUILD_DIR)/job-init \
     $(BUILD_DIR)/job-netd

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/jobd: $(COMMON_OBJS) $(BUILD_DIR)/jobd.o
	$(CC) $(ALL_CFLAGS) $^ -o $@ $(ALL_LDFLAGS)

$(BUILD_DIR)/jobctl: $(COMMON_OBJS) $(BUILD_DIR)/jobctl.o
	$(CC) $(ALL_CFLAGS) $^ -o $@ $(ALL_LDFLAGS)

$(BUILD_DIR)/job-init: $(SRC_DIR)/job_init.c | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) $< -o $@ $(ALL_LDFLAGS)

$(BUILD_DIR)/job-netd: $(SRC_DIR)/job_netd.c | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) $< -o $@ $(ALL_LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(LIBEXECDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)/jobd
	install -m 755 $(BUILD_DIR)/jobd     $(DESTDIR)$(BINDIR)/jobd
	install -m 755 $(BUILD_DIR)/jobctl   $(DESTDIR)$(BINDIR)/jobctl
	install -m 755 $(BUILD_DIR)/job-init $(DESTDIR)$(LIBEXECDIR)/job-init
	install -m 755 $(BUILD_DIR)/job-netd $(DESTDIR)$(LIBEXECDIR)/job-netd
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/jobd/jobd.conf ]; then \
		install -m 644 examples/jobd.conf \
			$(DESTDIR)$(SYSCONFDIR)/jobd/jobd.conf; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/jobd
	rm -f $(DESTDIR)$(BINDIR)/jobctl
	rm -f $(DESTDIR)$(LIBEXECDIR)/job-init
	rm -f $(DESTDIR)$(LIBEXECDIR)/job-netd

$(BUILD_DIR)/test_%: tests/unit/test_%.c $(COMMON_OBJS) | $(BUILD_DIR)
	$(CC) $(ALL_CFLAGS) $< $(COMMON_OBJS) -o $@ $(ALL_LDFLAGS)

test: $(TEST_BINS)
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "--- $$t"; \
		$$t || fail=1; \
	done; \
	exit $$fail

check: test

SAN_CFLAGS  = -fsanitize=address,undefined -fno-omit-frame-pointer \
              -fsanitize-address-use-after-scope
SAN_LDFLAGS = -fsanitize=address,undefined

sanitize:
	$(MAKE) clean
	$(MAKE) test EXTRA_CFLAGS="$(SAN_CFLAGS)" EXTRA_LDFLAGS="$(SAN_LDFLAGS)"
	$(MAKE) clean

lint:
	cppcheck --quiet --enable=warning,performance,portability \
		--check-level=reduced \
		--suppress=missingIncludeSystem \
		--suppress=normalCheckLevelMaxBranches \
		--inline-suppr --error-exitcode=1 -I$(INC_DIR) $(SRC_DIR)
	@command -v shellcheck >/dev/null 2>&1 && \
		shellcheck tests/integration.sh || \
		echo "shellcheck not installed, skipping"
