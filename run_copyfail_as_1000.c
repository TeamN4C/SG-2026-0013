// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	if (setresgid(1000, 1000, 1000) < 0)
		die("setresgid");
	if (setresuid(1000, 1000, 1000) < 0)
		die("setresuid");

	printf("[launcher] before child: ruid=%d euid=%d rgid=%d egid=%d\n",
	       getuid(), geteuid(), getgid(), getegid());
	fflush(stdout);

	pid_t pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		char *child_argv[] = { "/copyfail_probe", NULL };
		execv(child_argv[0], child_argv);
		fprintf(stderr, "[launcher] execv failed: %s\n", strerror(errno));
		_exit(127);
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0)
		die("waitpid");

	printf("[launcher] child status=0x%x\n", status);
	printf("[launcher] after child: ruid=%d euid=%d rgid=%d egid=%d\n",
	       getuid(), geteuid(), getgid(), getegid());

	if (WIFEXITED(status))
		printf("[launcher] child exited with code=%d\n", WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		printf("[launcher] child killed by signal=%d\n", WTERMSIG(status));

	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
