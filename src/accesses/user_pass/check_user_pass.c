#include <check.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "user_pass.h"


static char* ck_password = "TestPassword123!";


/*
 * Core tests
 */
// int prompt_up(uint8_t** up);
START_TEST (check_prompt_up)
{
	int old_stdin     = -1;
	int old_stdout    = -1;
	int new_stdin[2]  = {-1, -1};
	int new_stdout[2] = {-1, -1};
	uint8_t *up = NULL;
	int ret = FALSE;

	/* Prepare file descriptors for testing */
	if(pipe(new_stdin) == -1)
		ck_abort_msg("pipe(2) failed [1]: ", strerror(errno));
	if(pipe(new_stdout) == -1)
		ck_abort_msg("pipe(2) failed [2]: ", strerror(errno));

	old_stdin  = dup(STDIN_FILENO);
	old_stdout = dup(STDOUT_FILENO);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	dup2(new_stdin[0],  STDIN_FILENO);
	dup2(new_stdout[1], STDOUT_FILENO);

	/* Write the password as if it comes from a user input */
	if(fork() == 0)
	{
		size_t ck_password_len = strlen(ck_password);
		ssize_t wret = 0;

		ret = 0;

		wret = write(new_stdin[1], ck_password, ck_password_len);
		if(wret != (ssize_t)ck_password_len)
			ret = errno;

		wret = write(new_stdin[1], "\n", 1);
		if(wret != 1)
			ret = errno;

		_exit(ret);
	}

	/* Tested unit */
	ret = prompt_up(&up);

	/* Check unit outputs */
	ck_assert_int_eq(ret, TRUE);
	ck_assert_str_eq(up, ck_password);

	/* Putting every file descriptors back to normal */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	close(new_stdin[0]);
	close(new_stdin[1]);
	close(new_stdout[0]);
	close(new_stdout[1]);

	dup2(old_stdin,  STDIN_FILENO);
	dup2(old_stdout, STDOUT_FILENO);

	close(old_stdin);
	close(old_stdout);

	/* Check for child's status */
	if(wait(&ret) == -1)
		ck_abort_msg("Waiting for child failed: %s", strerror(errno));

	if(ret != 0)
		ck_abort_msg("Child failed: %s", strerror(ret));
}
END_TEST


// int user_key(const uint8_t *user_password, const uint8_t *salt, uint8_t *result_key);
START_TEST (check_user_key)
{
	uint8_t *user_password = NULL;
	uint8_t salt[16] = {0,};
	uint8_t *result_key = NULL;
	char good_key[] = {
		'\x39', '\xf5', '\x3f', '\xaf', '\x64', '\x09', '\x97', '\x2b',
		'\xb1', '\x2b', '\x8e', '\xb2', '\x44', '\xcb', '\x04', '\x40',
		'\x63', '\x57', '\x5c', '\xe5', '\xca', '\x3f', '\xce', '\x7f',
		'\xac', '\xc6', '\x8c', '\x66', '\x96', '\x2d', '\x94', '\xb6'
	};
	int ret = FALSE;

	user_password = (uint8_t*) ck_password;

	/* From function's documentation, size should be 32 */
	result_key = dis_malloc(32 * sizeof(char));
	memset(result_key, 0, 32 * sizeof(char));

	/* Tested unit */
	ret = user_key(user_password, salt, result_key);

	/* Check unit outputs */
	ck_assert_int_eq(ret, TRUE);
	if(memcmp(result_key, good_key, 32) != 0)
	{
		dis_free(result_key);
		ck_abort_msg("Found result key doesn't match what it should");
	}

	dis_free(result_key);
}
END_TEST


/*
 * Limit tests
 */
START_TEST (check_user_key_nullargs)
{
	uint8_t *uint8_notnull = malloc(4);


	ck_assert_int_eq(user_key(NULL, uint8_notnull, uint8_notnull), FALSE);
	ck_assert_int_eq(user_key(uint8_notnull, NULL, uint8_notnull), FALSE);
	ck_assert_int_eq(user_key(uint8_notnull, uint8_notnull, NULL), FALSE);

	free(uint8_notnull);
}
END_TEST

START_TEST (check_prompt_up_nullargs)
{
	ck_assert_int_eq(prompt_up(NULL), FALSE);
}
END_TEST


/*
 * Testing suite
 */
Suite* user_pass_suite(void)
{
	Suite *s = suite_create("User pass");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, check_user_key);
	tcase_add_test(tc_core, check_prompt_up);
	suite_add_tcase(s, tc_core);

	/* Limits tests case */
	TCase *tc_limits = tcase_create("Limits");
	tcase_add_test(tc_limits, check_user_key_nullargs);
	tcase_add_test(tc_limits, check_prompt_up_nullargs);
	/* TODO add more limits for more code coverage */
	suite_add_tcase(s, tc_limits);

	return s;
}


int main(void)
{
	int number_failed;

	xstdio_init(L_ERROR, NULL);

	Suite *s = user_pass_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free (sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
