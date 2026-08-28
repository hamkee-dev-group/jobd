#define _GNU_SOURCE
#include <string.h>

#include "jobd.h"
#include "testutil.h"

static void test_basic_append(void)
{
	TEST("append stays within the buffer");

	char store[32];
	struct agd_buf b;
	agd_buf_init(&b, store, sizeof(store));

	agd_buf_adds(&b, "hello");
	agd_buf_addch(&b, ' ');
	agd_buf_addf(&b, "%s%d", "world", 42);

	ASSERT(strcmp(store, "hello world42") == 0, "unexpected content");
	ASSERT(agd_buf_len(&b) == 13, "unexpected length");
	ASSERT(!agd_buf_truncated(&b), "should not report truncation");
	PASS();
}

static void test_truncation_is_bounded(void)
{
	TEST("truncation never writes past the end");

	char store[16];
	char canary[16];
	memset(canary, 0x7f, sizeof(canary));

	struct agd_buf b;
	agd_buf_init(&b, store, sizeof(store));

	for (int i = 0; i < 100; i++)
		agd_buf_addf(&b, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

	ASSERT(agd_buf_truncated(&b), "truncation should be reported");
	ASSERT(agd_buf_len(&b) < sizeof(store), "length must stay in bounds");
	ASSERT(store[sizeof(store) - 1] == '\0', "must remain NUL terminated");
	ASSERT(strlen(store) == sizeof(store) - 1, "should be filled exactly");

	for (size_t i = 0; i < sizeof(canary); i++)
		ASSERT(canary[i] == 0x7f, "wrote past the end of the buffer");
	PASS();
}

static void test_zero_capacity(void)
{
	TEST("zero capacity is safe");

	struct agd_buf b;
	agd_buf_init(&b, NULL, 0);
	agd_buf_adds(&b, "x");
	agd_buf_addf(&b, "%d", 1);
	agd_buf_addch(&b, 'y');

	ASSERT(agd_buf_len(&b) == 0, "nothing should be written");
	ASSERT(agd_buf_truncated(&b), "should report truncation");
	PASS();
}

static void test_toml_escaping(void)
{
	TEST("TOML escaping neutralises rule injection");

	char store[256];
	struct agd_buf b;
	agd_buf_init(&b, store, sizeof(store));

	agd_buf_add_toml(&b,
	                 "/tmp\"]\n  [[fs_layer.rule]]\n  path = \"/");

	ASSERT(strstr(store, "[[fs_layer.rule]]") == NULL ||
	       strstr(store, "\\n") != NULL,
	       "newline must be escaped");
	ASSERT(strchr(store, '\n') == NULL, "raw newline must not survive");
	ASSERT(strstr(store, "\\\"") != NULL, "quote must be escaped");
	PASS();
}

static void test_json_escaping(void)
{
	TEST("JSON escaping covers quotes and control characters");

	char store[256];
	struct agd_buf b;
	agd_buf_init(&b, store, sizeof(store));

	agd_buf_add_json(&b, "a\"b\\c\nd\te\x01");

	ASSERT(strstr(store, "\\\"") != NULL, "quote must be escaped");
	ASSERT(strstr(store, "\\\\") != NULL, "backslash must be escaped");
	ASSERT(strstr(store, "\\n") != NULL, "newline must be escaped");
	ASSERT(strstr(store, "\\t") != NULL, "tab must be escaped");
	ASSERT(strstr(store, "\\u0001") != NULL, "control char must be escaped");
	ASSERT(strchr(store, '\n') == NULL, "raw newline must not survive");
	PASS();
}

int main(void)
{
	printf("=== bounded buffer tests ===\n\n");

	test_basic_append();
	test_truncation_is_bounded();
	test_zero_capacity();
	test_toml_escaping();
	test_json_escaping();

	TEST_SUMMARY();
}
