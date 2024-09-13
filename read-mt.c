#define _GNU_SOURCE

#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <sched.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

static int num_thr;
static int max_thr;
static int fd;
static bool is_sum = false;
static bool is_affinity = false;
struct stat st;

static void *start_one(void *data)
{
	size_t bufsize = 131072;
	int idx = (uintptr_t) data;
	loff_t off = idx * bufsize;
	void *tmp;
	uint64_t *buf;
	int res;
	uint64_t sum = 0;

	res = posix_memalign(&tmp, 131072, bufsize);
	if (res) {
		errno = res;
		err(1, "allocating aligned buffer");
	}
	buf = tmp;

	for (; off < st.st_size; off += num_thr * bufsize) {
		res = pread(fd, buf, bufsize, off);
		if (res == -1)
			err(1, "read");

		if (is_sum) {
			for (size_t i = 0; i < res / sizeof(buf[0]); i++)
				sum += buf[i];
		}
	}

	return (void *) sum;
}

static uint64_t do_mt(void)
{
	pthread_t id[CPU_SETSIZE];
	int i, res, cnt;
	cpu_set_t set;
	uint64_t sum = 0;

	CPU_ZERO(&set);
	res = sched_getaffinity(0, sizeof(set), &set);
	if (res == -1)
		err(1, "sched_getaffinity()");
	num_thr = max_thr ?: CPU_COUNT(&set);

	for (cnt = 0; cnt < num_thr; cnt++) {
		if (is_affinity) {
			cpu_set_t one;

			if (cnt % CPU_COUNT(&set) == 0)
				i = 0;
			for (; !CPU_ISSET(i, &set); i++);
			CPU_ZERO(&one);
			CPU_SET(i, &one);
			res = sched_setaffinity(0, sizeof(one), &one);
			if (res == -1)
				err(1, "sched_setaffinity(%i)", i);
			i++;
		}

		res = pthread_create(&id[cnt], NULL, start_one, (void *)(uintptr_t)cnt);
		if (res != 0) {
			errno = res;
			err(1, "pthread_create");
		}
	}
	for (cnt = 0; cnt < num_thr; cnt++) {
		void *retval;

		res = pthread_join(id[cnt], &retval);
		if (res != 0) {
			errno = res;
			err(1, "pthread_join");
		}
		sum += (uint64_t) retval;
	}

	return sum;
}

static uint64_t do_plain(void)
{
	num_thr = 1;
	return (uint64_t) start_one((void *) 0);
}

int main(int argc, char *argv[])
{
	int res;
	uint64_t sum;
	int o_direct = 0;
	int cnt = 1;
	char *filename = NULL;
	struct timespec start, end;

	if (argc == 1)
		errx(1, "usage: %s filename [-d] [-s] [-p] [-m max_threads]", argv[0]);

	for (; cnt < argc; cnt++) {
		char *arg = argv[cnt];
		char *e;

		if (arg[0] != '-') {
			if (filename != NULL)
				errx(1, "unknown option: %s", arg);
			filename = arg;
		} else if (!arg[1] || arg[2]) {
			errx(1, "unknown option: %s", arg);
		} else {
			switch (arg[1]) {
			case 'd':
				o_direct = O_DIRECT;
				break;

			case 's':
				is_sum = true;
				break;

			case 'a':
				is_affinity = true;
				break;

			case 'm':
				cnt++;
				if (cnt == argc)
					errx(1, "missing parameter for %s", arg);
				arg = argv[cnt];
				errno = 0;
				max_thr = strtod(arg, &e);
				if (errno)
					err(1, "%s", arg);
				if (e == arg || *e != '\0' || max_thr < 1 || max_thr >= CPU_SETSIZE)
					errx(1, "invalid max_threads: %s", arg);
				break;

			default:
				errx(1, "unknown option: %s", arg);
			}
		}
	}

	fd = open(filename, O_RDONLY | o_direct);
	if (fd == -1)
		err(1, "open(%s)", argv[1]);

	res = fstat(fd, &st);
	if (res == -1)
		err(1, "fstat");

	clock_gettime(CLOCK_MONOTONIC, &start);
	if (max_thr == 1)
		sum = do_plain();
	else
		sum = do_mt();
	clock_gettime(CLOCK_MONOTONIC, &end);

	if (is_sum)
		printf("%lx\n", sum);
	else
		printf("%.4f GB/s\n", st.st_size / ((end.tv_sec - start.tv_sec) * 1000000000.0 + (end.tv_nsec - start.tv_nsec))); 
}
