#ifndef JOBD_TESTUTIL_H
#define JOBD_TESTUTIL_H

#include <stdio.h>

static int test_count;
static int fail_count;

#define TEST(name)   do { test_count++; printf("  %s... ", name); } while (0)
#define PASS()       do { printf("PASS\n"); } while (0)
#define FAIL(msg)    do { printf("FAIL: %s\n", msg); fail_count++; } while (0)
#define ASSERT(cond, msg) \
	do { if (!(cond)) { FAIL(msg); return; } } while (0)

#define TEST_SUMMARY()                                                     \
	do {                                                               \
		printf("\n%d tests, %d failed\n", test_count, fail_count); \
		return fail_count > 0 ? 1 : 0;                             \
	} while (0)

#endif
