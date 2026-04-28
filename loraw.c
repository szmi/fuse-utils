#define _GNU_SOURCE
#define LO_NOTHREAD 1

#include "fuse_kernel.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>
#include <sched.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <liburing.h>
#include <sys/xattr.h>
#include <sys/statvfs.h>

/* returns -1 on error */
#define ER(_expr) \
	({ typeof(_expr) _ret = (_expr); if (_ret == (typeof(_expr)) -1) err(1, #_expr); _ret; })
/* returns errno on error */
#define PE(_expr) \
	({ typeof(_expr) _ret = (_expr); if (_ret != 0) { errno = _ret; err(1, #_expr); } _ret; })
/* returns -errno on error */
#define NE(_expr) \
	({ typeof(_expr) _ret = (_expr); if (_ret < 0) { errno = -_ret; err(1, #_expr); } _ret; })
/* returns NULL on error */
#define NL(_expr) \
        ({ typeof(_expr) _ret = (_expr); if (_ret == NULL) { errx(1, #_expr " returned NULL"); } _ret; })

struct lo_fd {
	int fd;
	bool close;
};

static void cleanup_fd(struct lo_fd *fd)
{
        if (fd->close && fd->fd >= 0)
                close(fd->fd);
}

#define LO_FD(fd_) struct lo_fd __attribute__((cleanup(cleanup_fd))) fd_ = \
	{ .fd = -1, .close = false }

struct lo_inode {
	struct lo_inode *next; /* protected by lo->mutex */
	struct lo_inode *prev; /* protected by lo->mutex */
	int fd;
	int backing_id;
	dev_t dev;
	uint64_t refcount; /* protected by lo->mutex */
	struct fuse_attr attr;
};

struct lo_file {
	union {
		struct lo_file *next;
		int fd;
		struct {
			DIR *dp;
			struct dirent *entry;
			off_t offset;
		};
	};
};

struct lo_config {
	int debug;
	int single;
	int bind;
	int map;
	unsigned int mount_flags;
	uint64_t timeout;
	const char *source;
	const char *tag;
	int nothread;
	int direct;
	int uring;
	int queue_depth;
	size_t req_size;
	int passthrough;
	int passthrough2;
	int fusex;
	int no_open;
	const char *mnt;
};

struct lo_data {
	pthread_mutex_t mutex;
#ifdef LO_NOTHREAD
#define LO_INODE_MAX 65536
	struct lo_inode inodes[LO_INODE_MAX];
	struct lo_inode *free_inodes;
#define LO_FILE_MAX 65536
	struct lo_file files[LO_FILE_MAX];
	struct lo_file *free_files;
	sem_t sem;
#endif
	struct lo_config c;
	struct lo_inode root;
	int devfd;
	int mounted_fd;
};

struct lo_chan {
	int fd;
	void *inbuf;
	void *outbuf;
	size_t bufsize;
};

struct lo_ring_req {
	struct io_uring *ring;
	int qid;
	struct fuse_uring_req_header *rreq;
	struct iovec iov[2];
	uint64_t unique;
};

struct lo_req {
	struct lo_data *lo;
	int is_ch;
	union {
		struct lo_chan ch;
		struct lo_ring_req rr;
	};
};


#ifdef LO_NOTHREAD
static inline int lo_nothread(struct lo_data *lo)
{
	return lo->c.nothread;
}

static inline void lo_mutex_init_nt(struct lo_data *lo)
{
	sem_init(&lo->sem, 1, 1);
}

static inline void lo_mutex_lock_nt(struct lo_data *lo)
{
	sem_wait(&lo->sem);
}

static inline void lo_mutex_unlock_nt(struct lo_data *lo)
{
	sem_post(&lo->sem);
}

static inline struct lo_inode *lo_alloc_inode_nt(struct lo_data *lo)
{
	struct lo_inode *inode;

	lo_mutex_lock_nt(lo);
	inode = lo->free_inodes;
	if (inode)
		lo->free_inodes = inode->next;
	lo_mutex_unlock_nt(lo);

	memset(inode, 0, sizeof(*inode));

	return inode;
}

static inline struct lo_file *lo_alloc_file_nt(struct lo_data *lo)
{
	struct lo_file *lf;

	lo_mutex_lock_nt(lo);
	lf = lo->free_files;
	if (lf)
		lo->free_files = lf->next;
	lo_mutex_unlock_nt(lo);

	memset(lf, 0, sizeof(*lf));

	return lf;

}

static inline void lo_free_inode_locked_nt(struct lo_data *lo,
					   struct lo_inode *inode)
{
	inode->next = lo->free_inodes;
	lo->free_inodes = inode;
}

static inline void lo_free_file_locked_nt(struct lo_data *lo,
					  struct lo_file *lf)
{
	lf->next = lo->free_files;
	lo->free_files = lf;
}

static inline void lo_free_inode_nt(struct lo_data *lo, struct lo_inode *inode)
{
	lo_mutex_lock_nt(lo);
	lo_free_inode_locked_nt(lo, inode);
	lo_mutex_unlock_nt(lo);
}

static inline void lo_free_file_nt(struct lo_data *lo, struct lo_file *lf)
{
	lo_mutex_lock_nt(lo);
	lo_free_file_locked_nt(lo, lf);
	lo_mutex_unlock_nt(lo);
}

static inline struct lo_data *lo_alloc_lo_nt(void)
{
	struct lo_data *lo;
	unsigned int i;

	lo = ER(mmap(NULL, sizeof(struct lo_data), PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0));

	for (i = 0; i < LO_INODE_MAX; i++)
		lo_free_inode_locked_nt(lo, &lo->inodes[i]);
	for (i = 0; i < LO_FILE_MAX; i++)
		lo_free_file_locked_nt(lo, &lo->files[i]);

	return lo;
}
#else

#define lo_nothread(lo) ((void) lo, 0)
#define lo_alloc_inode_nt(lo) NULL
#define lo_alloc_file_nt(lo) NULL
#define lo_free_inode_nt(lo, inode) abort()
#define lo_free_file_nt(lo, lf) abort()
#define lo_alloc_lo_nt() NULL
#define lo_mutex_init_nt(lo) abort()
#define lo_mutex_lock_nt(lo) abort()
#define lo_mutex_unlock_nt(lo) abort()

#endif

static void lo_mutex_init(struct lo_data *lo)
{
	if (!lo_nothread(lo))
		pthread_mutex_init(&lo->mutex, NULL);
	else
		lo_mutex_init_nt(lo);
}

static void lo_mutex_lock(struct lo_data *lo)
{
	if (!lo_nothread(lo))
		pthread_mutex_lock(&lo->mutex);
	else
		lo_mutex_lock_nt(lo);
}

static void lo_mutex_unlock(struct lo_data *lo)
{
	if (!lo_nothread(lo))
		pthread_mutex_unlock(&lo->mutex);
	else
		lo_mutex_unlock_nt(lo);
}

static struct lo_inode *lo_alloc_inode(struct lo_data *lo)
{
	if (!lo_nothread(lo))
		return calloc(1, sizeof(struct lo_inode));
	else
		return lo_alloc_inode_nt(lo);
}

static struct lo_file *lo_alloc_file(struct lo_data *lo)
{
	if (!lo_nothread(lo))
		return calloc(1, sizeof(struct lo_file));
	else
		return lo_alloc_file_nt(lo);
}

static void lo_free_inode(struct lo_data *lo, struct lo_inode *inode)
{
	if (!lo_nothread(lo))
		free(inode);
	else
		lo_free_inode_nt(lo, inode);
}

static void lo_free_file(struct lo_data *lo, struct lo_file *lf)
{
	if (!lo_nothread(lo))
		free(lf);
	else
		lo_free_file_nt(lo, lf);
}

static struct lo_inode *lo_inode(struct lo_data *lo, uint64_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return &lo->root;
	else
		return (struct lo_inode *) (uintptr_t) ino;
}

static int lo_debug(struct lo_req *req)
{
	return req->lo->c.debug;
}

static void lo_reply_ch(struct lo_req *req, int error, size_t argsize)
{
	struct lo_chan *lc = &req->ch;
	struct fuse_in_header *inh = lc->inbuf;
	struct fuse_out_header *outh = lc->outbuf;

	outh->len = sizeof(struct fuse_out_header) + argsize;
	outh->error = -error;
	outh->unique = inh->unique;

	ER(write(lc->fd, lc->outbuf, outh->len));
}

static void lo_queue_uring(struct lo_req *req, int cmd_op)
{
	struct io_uring_sqe *sqe;
	struct fuse_uring_cmd_req *ureq;

	sqe = NL(io_uring_get_sqe(req->rr.ring));
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->fd = 0;
	sqe->rw_flags = 0;
	sqe->ioprio = 0;
	sqe->off = 0;
	sqe->cmd_op = cmd_op;
	sqe->__pad1 = 0;

	ureq = (struct fuse_uring_cmd_req *) sqe->cmd;
	ureq->qid = req->rr.qid;
	ureq->commit_id = req->rr.rreq->ring_ent_in_out.commit_id;
	ureq->flags = 0;
	io_uring_sqe_set_data(sqe, req);
}

static void lo_reply_uring(struct lo_req *req, int error, size_t argsize)
{
	struct fuse_uring_req_header *rreq = req->rr.rreq;
	struct fuse_out_header *out = (struct fuse_out_header *)&rreq->in_out;
	struct fuse_uring_ent_in_out *ent_in_out = &rreq->ring_ent_in_out;

	ent_in_out->payload_sz = argsize;
	out->len = sizeof(struct fuse_out_header) + argsize;
	out->error = -error;
	out->unique = req->rr.unique;

	lo_queue_uring(req, FUSE_IO_URING_CMD_COMMIT_AND_FETCH);
	NE(io_uring_submit(req->rr.ring));
}

static void lo_reply(struct lo_req *req, int error, size_t argsize)
{
	if (lo_debug(req)) {
		fprintf(stderr, "   error: %i, outsize: %zu\n", error,
			sizeof(struct fuse_out_header) + argsize);
	}
	if (req->is_ch)
		lo_reply_ch(req, error, argsize);
	else
		lo_reply_uring(req, error, argsize);
}

static void *lo_out_arg(struct lo_req *req)
{
	if (req->is_ch)
		return ((struct fuse_out_header *) req->ch.outbuf) + 1;
	else
		return req->rr.iov[1].iov_base;
}

static size_t lo_out_len(struct lo_req *req)
{
	if (req->is_ch)
		return req->ch.bufsize - sizeof(struct fuse_out_header);
	else
		return req->rr.iov[1].iov_len;
}

static bool lo_overflow(struct lo_req *req, size_t size)
{
	return size > lo_out_len(req);
}

static struct lo_fd lo_open_node2(struct lo_req *req, uint64_t nodeid, int flags)
{
	struct lo_inode *inode = lo_inode(req->lo, nodeid);
	char buf[64];

	if (flags == O_PATH)
		return (struct lo_fd) { .fd = inode->fd, .close = false };

	sprintf(buf, "/proc/self/fd/%i", inode->fd);
	return (struct lo_fd) { .fd = open(buf, flags), .close = true };
}

static struct lo_fd lo_open_node(struct lo_req *req, const struct fuse_in_header *inh, int flags)
{
	return lo_open_node2(req, inh->nodeid, flags);
}

static struct lo_file *lo_file(uint64_t fh)
{
	return (void *) (uintptr_t) fh;
}

static struct lo_fd lo_open_io(struct lo_req *req, struct fuse_in_header *inh, uint64_t fh,
			       int flags)
{
	if (req->lo->c.no_open)
		return lo_open_node(req, inh, flags);

	return (struct lo_fd) { .fd = lo_file(fh)->fd, .close = false };
}


static void lo_convert_stat(const struct statx *stat, struct fuse_attr *attr)
{
	memset(attr, 0, sizeof(*attr));

	attr->ino	= stat->stx_ino;
	attr->mode	= stat->stx_mode;
	attr->nlink	= stat->stx_nlink;
	attr->uid	= stat->stx_uid;
	attr->gid	= stat->stx_gid;
	attr->rdev	= makedev(stat->stx_rdev_major, stat->stx_rdev_minor);
	attr->size	= stat->stx_size;
	attr->blksize	= stat->stx_blksize;
	attr->blocks	= stat->stx_blocks;
	attr->atime	= stat->stx_atime.tv_sec;
	attr->mtime	= stat->stx_mtime.tv_sec;
	attr->ctime	= stat->stx_ctime.tv_sec;
	attr->atimensec	= stat->stx_atime.tv_nsec;
	attr->mtimensec	= stat->stx_mtime.tv_nsec;
	attr->ctimensec	= stat->stx_ctime.tv_nsec;
}

static void lo_getattr(struct lo_req *req, struct fuse_in_header *inh,
		       struct fuse_getattr_in *inarg)
{
	struct lo_data *lo = req->lo;
	struct lo_inode *inode = lo_inode(lo, inh->nodeid);
	struct fuse_attr_out *outarg = lo_out_arg(req);

	(void) inarg;

	if (lo_debug(req))
		fprintf(stderr, "lo_getattr(ino=%"PRIu64")\n", inh->nodeid);

	memset(outarg, 0, sizeof(*outarg));
	outarg->attr_valid = lo->c.timeout;
	outarg->attr_valid_nsec = 0;
	outarg->dummy = 0;
	outarg->attr = inode->attr;
	lo_reply(req, 0, sizeof(*outarg));
}

static int lo_set_time(int basefd, const char *name, const struct fuse_sx_time *time)
{
	char buf[32];
	char path[64];
	char xattr[32];

	snprintf(path, sizeof(path), "/proc/self/fd/%d", basefd);
	snprintf(buf, sizeof(buf), "%lld.%09d",
		 (unsigned long long) time->tv_sec, time->tv_nsec);
	snprintf(xattr, sizeof(xattr), "trusted.loraw.%s", name);
	return setxattr(path, xattr, buf, strlen(buf), 0);
}

static int lo_get_time(int basefd, const char *name, struct statx_timestamp *time,
		       struct statx *sx, unsigned int mask)
{
	char buf[32];
	char path[64];
	char xattr[32];
	int err;
	long long int sec;
	unsigned int nsec;

	snprintf(path, sizeof(path), "/proc/self/fd/%d", basefd);
	snprintf(xattr, sizeof(xattr), "trusted.loraw.%s", name);
	err = getxattr(path, xattr, buf, sizeof(buf) - 1);
	if (err == -1 && errno != ENODATA)
		return -1;

	if (err == -1)
		return 0;

	buf[err] = '\0';
	if (sscanf(buf, "%lld.%u", &sec, &nsec) == 2) {
		time->tv_sec = sec;
		time->tv_nsec = nsec;
		sx->stx_mask |= mask;
	} else {
		errno = EIO;
		return -1;
	}

	return 0;
}

static int lo_do_setstatx(int basefd, const struct fuse_statx *sx)
{
	int res;

	if (sx->mask & STATX_SIZE) {
		res = ftruncate(basefd, sx->size);
		if (res == -1)
			return -1;
	}
	if (sx->mask & (STATX_UID | STATX_GID)) {
		uid_t uid = -1;
		gid_t gid = -1;

		if (sx->mask & STATX_UID)
			uid = sx->uid;
		if (sx->mask & STATX_GID)
			gid = sx->gid;
		res = fchownat(basefd, "", uid, gid, AT_EMPTY_PATH);
		if (res == -1)
			return -1;
	}
	if (sx->mask & STATX_MODE) {
		res = fchmodat(basefd, "", sx->mode & 07777, AT_EMPTY_PATH);
		if (res == -1)
			return -1;
	}
	if (sx->mask & STATX_ATIME) {
		res = lo_set_time(basefd, "atime", &sx->atime);
		if (res == -1)
			return -1;
	}
	if (sx->mask & STATX_BTIME) {
		res = lo_set_time(basefd, "btime", &sx->btime);
		if (res == -1)
			return -1;
	}
	if (sx->mask & STATX_CTIME) {
		res = lo_set_time(basefd, "ctime", &sx->ctime);
		if (res == -1)
			return -1;
	}
	if (sx->mask & STATX_MTIME) {
		res = lo_set_time(basefd, "mtime", &sx->mtime);
		if (res == -1)
			return -1;
	}
	return 0;
}

static void lo_setstatx(struct lo_req *req, const struct fuse_in_header *inh,
			const struct fuse_setstatx_in *inarg)
{
	LO_FD(base);
	int res;
	struct fuse_statx_out *outarg = lo_out_arg(req);

	if (inarg->stat.mask & ~(STATX_SIZE | STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_UID | STATX_GID | STATX_MODE)) {
		lo_reply(req, EINVAL, 0);
		return;
	}

	base = lo_open_node(req, inh, (inarg->stat.mask & STATX_SIZE) ? O_WRONLY : O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	res = lo_do_setstatx(base.fd, &inarg->stat);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	memset(outarg, 0, sizeof(*outarg));
	lo_reply(req, 0, sizeof(*outarg));
}

static int lo_do_statx(struct lo_req *req, int basefd, struct fuse_statx_out *outarg)
{
	int err;
	struct statx stat;

	err = statx(basefd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
		    STATX_BASIC_STATS, &stat);
	if (err == -1)
		return -1;

	err = lo_get_time(basefd, "atime", &stat.stx_atime, &stat, STATX_ATIME);
	if (err == -1)
		return -1;
	err = lo_get_time(basefd, "btime", &stat.stx_btime, &stat, STATX_BTIME);
	if (err == -1)
		return -1;
	err = lo_get_time(basefd, "ctime", &stat.stx_ctime, &stat, STATX_CTIME);
	if (err == -1)
		return -1;
	err = lo_get_time(basefd, "mtime", &stat.stx_mtime, &stat, STATX_MTIME);
	if (err == -1)
		return -1;

	assert(sizeof(outarg->stat) == sizeof(stat));
	memcpy(&outarg->stat, &stat, sizeof(stat));
	outarg->attr_valid = req->lo->c.timeout;
	return 0;
}

static void lo_statx(struct lo_req *req, const struct fuse_in_header *inh,
		     const struct fuse_statx_in *inarg)
{
	LO_FD(base);
	int err;
	struct fuse_statx_out *outarg = lo_out_arg(req);

	(void) inarg;

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	memset(outarg, 0, sizeof(*outarg));
	err = lo_do_statx(req, base.fd, outarg);
	if (err) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, sizeof(*outarg));
}

static int filter_xattr(char *list, int size)
{
	int rem = size;

	while (rem) {
		int thislen = strlen(list);

		assert(thislen < rem);
		if (!strncmp(list, "trusted.loraw.", 14)) {
			memmove(list, list + thislen + 1, rem - thislen - 1);
			size -= thislen + 1;
		} else {
			list += thislen + 1;
		}
		rem -= thislen + 1;
	}
	return size;
}

static void lo_getxattr(struct lo_req *req, const struct fuse_in_header *inh,
			const struct fuse_getxattr_in *inarg, const char *name)
{
	LO_FD(base);
	int res;
	char path[64];
	void *value = lo_out_arg(req);

	if (lo_overflow(req, inarg->size)) {
		lo_reply(req, EOVERFLOW, 0);
		return;
	}

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	snprintf(path, sizeof(path), "/proc/self/fd/%d", base.fd);
	if (name)
		res = getxattr(path, name, value, inarg->size);
	else {
		res = listxattr(path, value, inarg->size);
		if (res > 0)
			res = filter_xattr(value, res);
	}
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, res);
}

static void lo_setxattr(struct lo_req *req, const struct fuse_in_header *inh,
			const struct fuse_setxattr_in *inarg, const char *name)
{
	LO_FD(base);
	int res;
	char path[64];
	const void *value = name + strlen(name) + 1;

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	snprintf(path, sizeof(path), "/proc/self/fd/%d", base.fd);
	res = setxattr(path, name, value, inarg->size, inarg->flags);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, res);
}

static void lo_removexattr(struct lo_req *req, const struct fuse_in_header *inh, const char *name)
{
	LO_FD(base);
	int res;
	char path[64];

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	snprintf(path, sizeof(path), "/proc/self/fd/%d", base.fd);
	res = removexattr(path, name);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, res);
}

static struct lo_inode *lo_find(struct lo_data *lo, struct statx *st)
{
	struct lo_inode *p;
	struct lo_inode *ret = NULL;

	lo_mutex_lock(lo);
	for (p = lo->root.next; p != &lo->root; p = p->next) {
		if (p->attr.ino == st->stx_ino && p->dev == makedev(st->stx_dev_major, st->stx_dev_minor)) {
			assert(p->refcount > 0);
			ret = p;
			ret->refcount++;
			break;
		}
	}
	lo_mutex_unlock(lo);
	return ret;
}

static void lo_reply_entry(struct lo_req *req, struct lo_inode *inode)
{
	struct fuse_entryx_out *outarg = lo_out_arg(req);

	memset(outarg, 0, sizeof(*outarg));
	outarg->nodeid = (uintptr_t) inode;
	lo_reply(req, 0, sizeof(*outarg));
}

static void lo_lookup_root(struct lo_req *req, const struct fuse_in_header *inh)
{
	struct lo_data *lo = req->lo;

	(void) inh;

	lo_reply_entry(req, &lo->root);
}

static struct lo_inode *lo_new_inode(struct lo_data *lo, int fd, const struct statx *stat)
{
	struct lo_inode *prev, *next, *inode;

	inode = lo_alloc_inode(lo);
	if (!inode)
		return NULL;

	inode->refcount = 1;
	inode->fd = fd;
	inode->dev = makedev(stat->stx_dev_major, stat->stx_dev_minor);
	lo_convert_stat(stat, &inode->attr);

	lo_mutex_lock(lo);
	prev = &lo->root;
	next = prev->next;
	next->prev = inode;
	inode->next = next;
	inode->prev = prev;
	prev->next = inode;
	lo_mutex_unlock(lo);

	return inode;
}

static void lo_lookupx(struct lo_req *req, const struct fuse_in_header *inh, const char *name)
{
	struct lo_data *lo = req->lo;
	struct lo_inode *inode, *parent = lo_inode(lo, inh->nodeid);
	struct fuse_entryx_out *outarg = lo_out_arg(req);
	struct statx stat;
	int newfd;

	if (lo_debug(req)) {
		fprintf(stderr, " lo_lookupx(parent=%"PRIu64", name=%s)\n",
			inh->nodeid, name);
	}

	outarg->entry_valid = lo->c.timeout;
	newfd = openat(parent->fd, name, O_PATH | O_NOFOLLOW);
	if (newfd == -1) {
		if (errno != ENOENT) {
			lo_reply(req, errno, 0);
			return;
		}
		memset(outarg, 0, sizeof(*outarg));
		outarg->flags = FUSE_ENTRYX_NEGATIVE;
		lo_reply(req, 0, sizeof(*outarg));
		return;
	}

	ER(statx(newfd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS,  &stat));

	inode = lo_find(lo, &stat);
	if (inode) {
		close(newfd);
		newfd = -1;
	} else {
		inode = lo_new_inode(lo, newfd, &stat);
		if (!inode) {
			lo_reply(req, ENOMEM, 0);
			close(newfd);
			return;
		}
	}
	lo_reply_entry(req, inode);
}

static void lo_lookup(struct lo_req *req, struct fuse_in_header *inh,
		      char *name)
{
	struct lo_data *lo = req->lo;
	struct lo_inode *inode, *parent = lo_inode(lo, inh->nodeid);
	struct fuse_entry_out *outarg = lo_out_arg(req);
	struct statx stat;
	int newfd, res, saverr;

	if (lo_debug(req)) {
		fprintf(stderr, " lo_lookup(parent=%"PRIu64", name=%s)\n",
			inh->nodeid, name);
	}

	newfd = openat(parent->fd, name, O_PATH | O_NOFOLLOW);
	if (newfd == -1)
		goto out_err;

	res = statx(newfd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS,  &stat);
	if (res == -1)
		goto out_err;

	inode = lo_find(lo, &stat);
	if (inode) {
		close(newfd);
		newfd = -1;
	} else {
		struct lo_inode *prev, *next;

		saverr = ENOMEM;
		inode = lo_alloc_inode(lo);
		if (!inode)
			goto out_err;

		inode->refcount = 1;
		inode->fd = newfd;
		inode->dev = makedev(stat.stx_dev_major, stat.stx_dev_minor);
		lo_convert_stat(&stat, &inode->attr);

		lo_mutex_lock(lo);
		prev = &lo->root;
		next = prev->next;
		next->prev = inode;
		inode->next = next;
		inode->prev = prev;
		prev->next = inode;
		lo_mutex_unlock(lo);
	}
	memset(outarg, 0, sizeof(*outarg));
	outarg->nodeid = (uintptr_t) inode;
	outarg->entry_valid = lo->c.timeout;
	outarg->attr_valid = lo->c.timeout;
	outarg->attr = inode->attr;

	lo_reply(req, 0, sizeof(*outarg));
	return;

out_err:
	saverr = errno;
	if (newfd != -1)
		close(newfd);
	lo_reply(req, saverr, 0);
}

static void lo_mkobjx(struct lo_req *req, const struct fuse_in_header *inh,
		      const struct fuse_mkobjx_in *arg, const char *name)
{
	struct lo_data *lo = req->lo;
	LO_FD(base);
	struct lo_inode *inode;
	int newfd, res;
	struct statx st;
	struct fuse_statx stat;
	char proc_path[64];
	int tmpfile_fd = -1;
	int open_flags = O_PATH | O_NOFOLLOW;

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	if (S_ISDIR(arg->stat.mode)) {
		res = mkdirat(base.fd, name, arg->stat.mode);
	} else if (S_ISLNK(arg->stat.mode)) {
		res = symlinkat(name + arg->namesize, base.fd, name);
	} else if (arg->flags & FUSE_MKOBJX_TMPFILE) {
		snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", base.fd);
		res = tmpfile_fd = open(proc_path, O_TMPFILE | O_RDWR, arg->stat.mode);
		if (res != -1) {
			snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", tmpfile_fd);
			name = proc_path;
			open_flags = O_PATH;
		}
	} else {
		res = mknodat(base.fd, name, arg->stat.mode,
			      makedev(arg->stat.rdev_major, arg->stat.rdev_minor));
	}
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	newfd = openat(base.fd, name, open_flags);
	if (newfd == -1) {
		lo_reply(req, errno, 0);
		if (tmpfile_fd != -1)
			close(tmpfile_fd);
		return;
	}
	if (tmpfile_fd != -1)
		close(tmpfile_fd);

	stat = arg->stat;
	stat.mask &= STATX_UID | STATX_GID | STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_BTIME | STATX_MODE;
	if (S_ISLNK(stat.mode))
		stat.mask &= ~STATX_MODE;
	res = lo_do_setstatx(newfd, &stat);
	if (res == -1) {
		lo_reply(req, errno, 0);
		close(newfd);
		return;
	}
	ER(statx(newfd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS,  &st));
	assert(!lo_find(lo, &st));
	inode = lo_new_inode(lo, newfd, &st);
	if (!inode) {
		lo_reply(req, ENOMEM, 0);
		close(newfd);
		return;
	}
	lo_reply_entry(req, inode);
#if 0
	struct fuse_file_handle *handle;

	handle = lo_lookup_handle(req, newfd);
	if (handle) {
		if (arg->flags & FUSE_MKOBJX_TMPFILE)
			lo_save_unlinked(req, newfd, handle);
		else
			close(newfd);
	}
	lo_reply_handle(req, handle);
#endif
}

static void lo_maybe_save_unlinked(struct lo_req *req, int fd)
{
	(void) req;
#if 0
	struct stat st;

	ER(fstatat(fd, "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));
	if (st.st_nlink) {
		close(fd);
	} else {
		struct fuse_file_handle *handle = lo_lookup_handle(req, fd);

		if (!handle) {
			lo_reply(req, errno, 0);
			close(fd);
			return;
		}
		lo_save_unlinked(req, fd, handle);
	}
#endif
	close(fd);
}

static void lo_remove(struct lo_req *req, const struct fuse_in_header *inh, const char *name,
		      bool isdir)
{
	LO_FD(base);
	int res, fd;

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	fd = openat(base.fd, name, O_PATH | O_NOFOLLOW);
	if (fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	res = unlinkat(base.fd, name, isdir ? AT_REMOVEDIR : 0);
	if (res == -1) {
		lo_reply(req, errno, 0);
		close(fd);
		return;
	}
	lo_maybe_save_unlinked(req, fd);

	lo_reply(req, 0, 0);
}

static void lo_rename(struct lo_req *req, const struct fuse_in_header *inh,
		      const struct fuse_rename2_in *arg, const char *oldname)
{
	const char *newname = oldname + strlen(oldname) + 1;
	LO_FD(olddir);
	LO_FD(newdir);
	int fd, res;

	olddir = lo_open_node(req, inh, O_PATH);
	if (olddir.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	newdir = lo_open_node2(req, arg->newdir, O_PATH);
	if (newdir.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	fd = openat(newdir.fd, newname, O_PATH | O_NOFOLLOW);
	if (fd == -1 && errno != ENOENT) {
		lo_reply(req, errno, 0);
		return;
	}
	res = renameat2(olddir.fd, oldname, newdir.fd, newname, arg->flags);
	if (res == -1) {
		lo_reply(req, errno, 0);
		if (fd != -1)
			close(fd);
		return;
	}
	if (fd != -1)
		lo_maybe_save_unlinked(req, fd);

	lo_reply(req, 0, 0);
}

static void lo_link(struct lo_req *req, const struct fuse_in_header *inh,
		    const struct fuse_link_in *arg, const char *newname)
{
	LO_FD(newdir);
	LO_FD(old);
	int res;
	struct stat st;

	newdir = lo_open_node(req, inh, O_PATH);
	if (newdir.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	old = lo_open_node2(req, arg->oldnodeid, O_PATH);
	if (old.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}
	ER(fstatat(old.fd, "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));

	res = linkat(old.fd, "", newdir.fd, newname, AT_EMPTY_PATH);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}
#if 0
	if (!st.st_nlink)
		lo_delete_handle(req->lo, req->h2, arg->oldnodeid);
#endif

	lo_reply(req, 0, 0);
}

static int lo_backing_open(struct lo_data *lo, int fd)
{
	struct fuse_backing_map map = { .fd = fd };
	int backing_id;

	backing_id = ER(ioctl(lo->devfd, FUSE_DEV_IOC_BACKING_OPEN, &map));

	if (lo->c.debug)
		fprintf(stderr, "backing_open(%i) = %i\n", fd, backing_id);

	return backing_id;
}

static void lo_backing_close(struct lo_data *lo, int backing_id)
{
	if (lo->c.debug)
		fprintf(stderr, "backing_close(%i)\n", backing_id);

	ER(ioctl(lo->devfd, FUSE_DEV_IOC_BACKING_CLOSE, &backing_id));
}

static void lo_open(struct lo_req *req, struct fuse_in_header *inh,
		    struct fuse_open_in *inarg)
{
	struct lo_data *lo = req->lo;
	struct lo_inode *inode = lo_inode(lo, inh->nodeid);
	struct fuse_open_out *outarg = lo_out_arg(req);
	struct lo_file *lf;
	char buf[64];
	int fd;
	int o_direct = lo->c.direct ? O_DIRECT : 0;

	if (lo->c.passthrough) {
		if (!inode->backing_id)
			inode->backing_id = lo_backing_open(lo, inode->fd);
		memset(outarg, 0, sizeof(*outarg));
		outarg->open_flags = FOPEN_PASSTHROUGH;
		outarg->backing_id = inode->backing_id;
		lo_reply(req, 0, sizeof(*outarg));
		return;
	}

	sprintf(buf, "/proc/self/fd/%i", inode->fd);
	fd = open(buf, (inarg->flags & O_ACCMODE) | o_direct);
	if (fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lf = NL(lo_alloc_file(lo));

	memset(outarg, 0, sizeof(*outarg));
	outarg->fh = (uintptr_t) lf;
	outarg->open_flags = FOPEN_KEEP_CACHE;

	if (lo->c.passthrough2) {
		int backing_id = lo_backing_open(lo, fd);

		outarg->open_flags = FOPEN_PASSTHROUGH;
		outarg->backing_id = backing_id;
		close(fd);
		lf->fd = backing_id;
	} else {
		lf->fd = fd;
	}

	lo_reply(req, 0, sizeof(*outarg));
}

static void lo_release(struct lo_req *req, struct fuse_in_header *inh,
		       struct fuse_release_in *inarg)
{
	struct lo_file *lf = lo_file(inarg->fh);

	(void) inh;

	/* No lo_file for passthrough */
	if (lf) {
		if (req->lo->c.passthrough2)
			lo_backing_close(req->lo, lf->fd);
		else
			close(lf->fd);
		lo_free_file(req->lo, lf);
	}
	lo_reply(req, 0, 0);
}

static void lo_read(struct lo_req *req, struct fuse_in_header *inh,
		    struct fuse_read_in *inarg)
{
	char *outarg = lo_out_arg(req);
	ssize_t res;
	LO_FD(io);

	if (lo_overflow(req, inarg->size)) {
		lo_reply(req, EOVERFLOW, 0);
		return;
	}

	io = lo_open_io(req, inh, inarg->fh, O_RDONLY);
	if (io.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	res = pread(io.fd , outarg, inarg->size, inarg->offset);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, res);
}

static void lo_write(struct lo_req *req, struct fuse_in_header *inh,
		     struct fuse_write_in *inarg, void *data)
{
	struct fuse_write_out *outarg = lo_out_arg(req);
	ssize_t res;
	LO_FD(io);

	io = lo_open_io(req, inh, inarg->fh, O_WRONLY);
	if (io.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	res = pwrite(io.fd, data, inarg->size, inarg->offset);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	memset(outarg, 0, sizeof(*outarg));
	outarg->size = res;
	lo_reply(req, 0, sizeof(*outarg));
}

static void lo_fallocate(struct lo_req *req, struct fuse_in_header *inh,
			 struct fuse_fallocate_in *inarg)
{
	LO_FD(io);
	int res;

	io = lo_open_io(req, inh, inarg->fh, O_WRONLY);
	if (io.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	res = fallocate(io.fd, inarg->mode, inarg->offset, inarg->length);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, 0);
}

static void lo_readlink(struct lo_req *req, struct fuse_in_header *inh)
{
	char *outarg = lo_out_arg(req);
	size_t outlen = lo_out_len(req);
	ssize_t res;
	LO_FD(base);

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	res = readlinkat(base.fd, "", outarg, outlen);
	if (res == -1)
		lo_reply(req, errno, 0);
	else if ((size_t) res == outlen)
		lo_reply(req, ENAMETOOLONG, 0);
	else
		lo_reply(req, 0, res);
}

static void lo_statfs(struct lo_req *req, struct fuse_in_header *inh)
{
	struct fuse_statfs_out *outarg = lo_out_arg(req);
	LO_FD(base);
	int res;
	struct statvfs buf;

	base = lo_open_node(req, inh, O_PATH);
	if (base.fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	res = fstatvfs(base.fd, &buf);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	memset(outarg, 0, sizeof(*outarg));
	outarg->st.bsize	= buf.f_bsize;
	outarg->st.frsize	= buf.f_frsize;
	outarg->st.blocks	= buf.f_blocks;
	outarg->st.bfree	= buf.f_bfree;
	outarg->st.bavail	= buf.f_bavail;
	outarg->st.files	= buf.f_files;
	outarg->st.ffree	= buf.f_ffree;
	outarg->st.namelen	= buf.f_namemax;

	lo_reply(req, 0, sizeof(*outarg));
}

static void lo_opendir(struct lo_req *req, struct fuse_in_header *inh,
		       struct fuse_open_in *inarg)
{
	struct lo_data *lo = req->lo;
	struct lo_inode *inode = lo_inode(lo, inh->nodeid);
	struct fuse_open_out *outarg = lo_out_arg(req);
	struct lo_file *lf;
	int fd;
	DIR *dp;

	(void) inarg;

	fd = openat(inode->fd, ".", O_RDONLY);
	if (fd == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	dp = fdopendir(fd);
	if (dp == NULL) {
		int saverr = errno;

		close(fd);
		lo_reply(req, saverr, 0);
		return;
	}

	lf = NL(lo_alloc_file(lo));

	memset(outarg, 0, sizeof(*outarg));
	outarg->fh = (uintptr_t) lf;
	outarg->open_flags = 0;

	lf->dp = dp;

	lo_reply(req, 0, sizeof(*outarg));
}

static void lo_releasedir(struct lo_req *req, struct fuse_in_header *inh,
		       struct fuse_release_in *inarg)
{
	struct lo_file *lf = lo_file(inarg->fh);

	(void) inh;

	closedir(lf->dp);

	lo_free_file(req->lo, lf);
	lo_reply(req, 0, 0);
}

static void lo_readdir(struct lo_req *req, struct fuse_in_header *inh,
		       struct fuse_read_in *inarg)
{
	void *p = lo_out_arg(req);
	struct lo_file *lf = lo_file(inarg->fh);
	size_t rem = inarg->size, orig_size = inarg->size;
	int err = 0;
	const char *name;
	size_t namelen, entlen, entlen_padded;
	struct fuse_dirent *dirent;
	off_t nextoff;

	(void) inh;

	if (lo_overflow(req, inarg->size)) {
		lo_reply(req, EOVERFLOW, 0);
		return;
	}

	if ((off_t) inarg->offset != lf->offset) {
		seekdir(lf->dp, inarg->offset);
		lf->entry = NULL;
		lf->offset = inarg->offset;
	}
	while (1) {
		if (!lf->entry) {
			errno = 0;
			lf->entry = readdir(lf->dp);
			if (!lf->entry) {
				if (errno) {
					err = errno;
					break;
				} else {
					break; 
				}
			}
		}
		nextoff = lf->entry->d_off;
		name = lf->entry->d_name;
		namelen = strlen(name);
		entlen = FUSE_NAME_OFFSET + namelen;
		entlen_padded = FUSE_DIRENT_ALIGN(entlen);
		if (entlen_padded > rem)
			break;

		dirent = (struct fuse_dirent *) p;

		dirent->ino = lf->entry->d_ino;
		dirent->off = nextoff;
		dirent->namelen = namelen;
		dirent->type = lf->entry->d_type;
		memcpy(dirent->name, name, namelen);
		memset(dirent->name + namelen, 0, entlen_padded - entlen);

		p += entlen_padded;
		rem -= entlen_padded;

		lf->entry = NULL;
		lf->offset = nextoff;
	}

	if (err && rem == orig_size)
		lo_reply(req, err, 0);
	else
		lo_reply(req, 0, orig_size - rem);
}

static void unref_inode(struct lo_data *lo, struct lo_inode *inode, uint64_t n)
{
	if (!inode)
		return;

	lo_mutex_lock(lo);
	assert(inode->refcount >= n);
	inode->refcount -= n;
	if (!inode->refcount) {
		struct lo_inode *prev, *next;

		prev = inode->prev;
		next = inode->next;
		next->prev = prev;
		prev->next = next;
		lo_mutex_unlock(lo);

		if (inode->backing_id)
			lo_backing_close(lo, inode->backing_id);

		close(inode->fd);
		lo_free_inode(lo, inode);
	} else {
		lo_mutex_unlock(lo);
	}
}

static void lo_forget_one(struct lo_data *lo, uint64_t nodeid,
			  uint64_t nlookup)
{
	struct lo_inode *inode = lo_inode(lo, nodeid);

	if (lo->c.debug) {
		fprintf(stderr, "  forget %"PRIu64" %"PRIu64" -%"PRIu64"\n",
			nodeid, inode->refcount, nlookup);
	}

	unref_inode(lo, inode, nlookup);

}

static void lo_forget(struct lo_data *lo, struct fuse_in_header *inh,
		      struct fuse_forget_in *inarg)
{
	lo_forget_one(lo, inh->nodeid, inarg->nlookup);
}

static void lo_batch_forget(struct lo_data *lo, struct fuse_in_header *inh,
			    struct fuse_batch_forget_in *inarg,
			    struct fuse_forget_one *param)
{
	unsigned int i;

	(void) inh;

	if (!param)
		param = (void *) (inarg + 1);

	for (i = 0; i < inarg->count; i++)
		lo_forget_one(lo, param[i].nodeid, param[i].nlookup);
}

static void lo_init(struct lo_req *req, struct fuse_in_header *inh,
		    struct fuse_init_in *inarg)
{
	struct fuse_init_out *outarg = lo_out_arg(req);
	uint64_t inflags = inarg->flags;
	uint64_t outflags;

	(void) inh;
	memset(outarg, 0, sizeof(*outarg));

	if (inflags & FUSE_INIT_EXT)
		inflags |= (uint64_t) inarg->flags2 << 32;

	outflags = inflags & (FUSE_PARALLEL_DIROPS | FUSE_ASYNC_READ | FUSE_ASYNC_DIO | FUSE_INIT_EXT);
	if (req->lo->c.passthrough || req->lo->c.passthrough2) {
		if (!(inflags & FUSE_PASSTHROUGH))
			errx(1, "passthrough mode not supported");
		outflags |= FUSE_PASSTHROUGH;
		outarg->max_stack_depth = 1;
	}

	if (req->lo->c.uring && !(inflags & FUSE_OVER_IO_URING))
		errx(1, "uring mode not supported");

	outarg->flags = outflags;
	if (outflags & FUSE_INIT_EXT)
		outarg->flags2 = outflags >> 32;
	outarg->major = FUSE_KERNEL_VERSION;
	outarg->minor = FUSE_KERNEL_MINOR_VERSION;
	outarg->max_readahead = inarg->max_readahead;
	outarg->max_write = 131072;
	outarg->max_pages = 32;

	lo_reply(req, 0, sizeof(*outarg));
}

#define PAYLOAD_IS_ARG -999

static const struct { int off; bool is_name; } lo_payload_desc[256] = {
	[FUSE_LOOKUP]		= { PAYLOAD_IS_ARG, true },
	[FUSE_LOOKUPX]		= { PAYLOAD_IS_ARG, true },
	[FUSE_REMOVEXATTR]	= { PAYLOAD_IS_ARG, true },
	[FUSE_UNLINK]		= { PAYLOAD_IS_ARG, true },
	[FUSE_RMDIR]		= { PAYLOAD_IS_ARG, true },
	[FUSE_GETXATTR]		= { sizeof(struct fuse_getxattr_in), true },
	[FUSE_SETXATTR]		= { sizeof(struct fuse_setxattr_in), true },
	[FUSE_MKNOD]		= { sizeof(struct fuse_mknod_in), true },
	[FUSE_MKOBJX]		= { sizeof(struct fuse_mkobjx_in), true },
	[FUSE_RENAME2]		= { sizeof(struct fuse_rename2_in), true },
	[FUSE_LINK]		= { sizeof(struct fuse_link_in), true },
	[FUSE_WRITE]		= { sizeof(struct fuse_write_in), false },
	[FUSE_BATCH_FORGET]	= { sizeof(struct fuse_batch_forget_in), false },
};

static size_t lo_getreq(struct lo_chan *lc)
{
	ssize_t res;

	res = ER(read(lc->fd, lc->inbuf, lc->bufsize));
	if ((size_t) res < sizeof(struct fuse_in_header))
		errx(1, "short read from fuse device");
	return res;
}

static void lo_process(struct lo_req *req, struct fuse_in_header *inh,
		       void *arg, void *payload, size_t len, struct io_uring_cqe *cqe)
{
	assert(inh->opcode < sizeof(lo_payload_desc) / sizeof(lo_payload_desc[0]));

	int off = lo_payload_desc[inh->opcode].off;
	if (req->is_ch) {
		assert(payload == NULL);
		if (off) {
			if (off == PAYLOAD_IS_ARG)
				payload = arg;
			else
				payload = arg + off;
		}
	} else {
		if (off)
			assert(len > 0);
		else
			assert(len == 0);
	}

	if (lo_debug(req)) {
		fprintf(stderr,
			"%cunique: %"PRIu64", opcode: %i, nodeid: %16"PRIx64", insize: %zu, name: <%s>\n",
			req->is_ch ? ' ' : cqe ? '.' : '*',
			inh->unique, inh->opcode, inh->nodeid, len,
			lo_payload_desc[inh->opcode].is_name ? (char *) payload : "NULL");
	}

	switch (inh->opcode) {
	case FUSE_INIT:
		lo_init(req, inh, arg);
		break;

	case FUSE_LOOKUP_ROOT:
		lo_lookup_root(req, inh);
		break;

	case FUSE_LOOKUPX:
		lo_lookupx(req, inh, payload);
 		break;

	case FUSE_LOOKUP:
		lo_lookup(req, inh, payload);
		break;

	case FUSE_STATX:
		lo_statx(req, inh, arg);
		break;

	case FUSE_GETATTR:
		lo_getattr(req, inh, arg);
		break;

	case FUSE_SETSTATX:
		lo_setstatx(req, inh, arg);
		break;

	case FUSE_GETXATTR:
		lo_getxattr(req, inh, arg, payload);
		break;

	case FUSE_LISTXATTR:
		lo_getxattr(req, inh, arg, NULL);
		break;

	case FUSE_SETXATTR:
		lo_setxattr(req, inh, arg, payload);
		break;

	case FUSE_REMOVEXATTR:
		lo_removexattr(req, inh, payload);
		break;

	case FUSE_READLINK:
		lo_readlink(req, inh);
		break;

	case FUSE_STATFS:
		lo_statfs(req, inh);
		break;

	case FUSE_MKOBJX:
		lo_mkobjx(req, inh, arg, payload);
		break;

	case FUSE_UNLINK:
		lo_remove(req, inh, payload, false);
		break;

	case FUSE_RMDIR:
		lo_remove(req, inh, payload, true);
		break;

	case FUSE_RENAME2:
		lo_rename(req, inh, arg, payload);
		break;

	case FUSE_LINK:
		lo_link(req, inh, arg, payload);
		break;

	case FUSE_OPEN:
		lo_open(req, inh, arg);
		break;

	case FUSE_RELEASE:
		lo_release(req, inh, arg);
		break;

	case FUSE_READ:
		lo_read(req, inh, arg);
		break;

	case FUSE_WRITE:
		lo_write(req, inh, arg, payload);
		break;

	case FUSE_FALLOCATE:
		lo_fallocate(req, inh, arg);
		break;

	case FUSE_OPENDIR:
		lo_opendir(req, inh, arg);
		break;

	case FUSE_RELEASEDIR:
		lo_releasedir(req, inh, arg);
		break;

	case FUSE_READDIR:
		lo_readdir(req, inh, arg);
		break;

	case FUSE_FORGET:
		lo_forget(req->lo, inh, arg);
		break;

	case FUSE_BATCH_FORGET:
		lo_batch_forget(req->lo, inh, arg, payload);
		break;

	default:
		lo_reply(req, ENOSYS, 0);
	}
}

static void lo_alloc_bufs(struct lo_chan *lc)
{
	size_t outbuf_align = 0x20000;
	size_t outbuf_allocsize =  0x60000;
	size_t outbuf_offset = outbuf_align - sizeof(struct fuse_out_header);

	lc->bufsize = 0x21000;
	PE(posix_memalign(&lc->inbuf, 0x1000, lc->bufsize));
	assert(outbuf_offset + lc->bufsize <= outbuf_allocsize);
	PE(posix_memalign(&lc->outbuf, outbuf_align, outbuf_allocsize));
	lc->outbuf += outbuf_offset;
}

struct lo_thread_data {
	struct lo_data *lo;
	int cpu;
};

static void lo_start_uring(struct lo_thread_data *ltd)
{
	int fd, i;
	struct lo_data *lo = ltd->lo;
	struct io_uring ring;
	struct lo_req *req;

	fd = lo->devfd;

	NE(io_uring_queue_init(lo->c.queue_depth, &ring, IORING_SETUP_SQE128));
	NE(io_uring_register_files(&ring, &fd, 1));

	for (i = 0; i < lo->c.queue_depth; i++) {
		struct io_uring_sqe *sqe;
		struct fuse_uring_cmd_req *ureq;

		req = NL(calloc(1, sizeof(*req)));

		req->lo = lo;
		req->is_ch = 0;
		req->rr.ring = &ring,
		req->rr.qid = ltd->cpu;

		/* Allocate header buffer (page-aligned) */
		PE(posix_memalign((void **) &req->rr.rreq, 0x1000, sizeof(struct fuse_uring_req_header)));

		/* Allocate payload buffer (page-aligned) */
		req->rr.iov[1].iov_len = lo->c.req_size;
		PE(posix_memalign((void **) &req->rr.iov[1].iov_base, 0x1000, req->rr.iov[1].iov_len));

		if (lo->c.debug) {
			fprintf(stderr, "NEW req=%p rreq=%p qid=%i\n",
				req, req->rr.rreq, req->rr.qid);
		}

		sqe = NL(io_uring_get_sqe(&ring));
		sqe->opcode = IORING_OP_URING_CMD;
		sqe->flags = IOSQE_FIXED_FILE;
		sqe->fd = 0;
		sqe->cmd_op = FUSE_IO_URING_CMD_REGISTER;

		req->rr.iov[0].iov_base = req->rr.rreq;
		req->rr.iov[0].iov_len = sizeof(struct fuse_uring_req_header);
		sqe->addr = (unsigned long) req->rr.iov;
		sqe->len = 2;

		ureq = (struct fuse_uring_cmd_req *) sqe->cmd;
		ureq->qid = req->rr.qid;
		io_uring_sqe_set_data(sqe, req);
	}
	NE(io_uring_submit(&ring));

	for (;;) {
		struct fuse_uring_req_header *rreq;
		struct io_uring_cqe *cqe;
		struct fuse_in_header *in;
		struct fuse_uring_ent_in_out *ent_in_out;

		NE(io_uring_wait_cqe(&ring, &cqe));

		req = io_uring_cqe_get_data(cqe);
		rreq = req->rr.rreq;
		in = (struct fuse_in_header *)&rreq->in_out;
		ent_in_out = &rreq->ring_ent_in_out;


		if (lo->c.debug) {
			fprintf(stderr, "CQE res=%d, commit_id=%lu, payload_sz=%u req=%p\n",
				cqe->res, ent_in_out->commit_id, ent_in_out->payload_sz, req);
		}
		assert(!cqe->res);
		req->rr.unique = in->unique;
		lo_process(req, in, rreq->op_in, req->rr.iov[1].iov_base, ent_in_out->payload_sz, cqe);
		io_uring_cqe_seen(req->rr.ring, cqe);
	}
}

static void lo_start_threads(struct lo_data *lo);

static void lo_loop(struct lo_data *lo, int fd)
{
	struct lo_req req = {
		.lo = lo,
		.is_ch =1,
		.ch.fd = fd,
	};

	lo_alloc_bufs(&req.ch);

	while (1) {
		struct fuse_in_header *inh = req.ch.inbuf;
		void *arg = inh + 1;
		size_t len;

		len = lo_getreq(&req.ch);
		lo_process(&req, inh, arg, NULL, len, NULL);

		if (lo->mounted_fd != -1) {
			struct pollfd fd = { .fd = lo->mounted_fd };

			ER(poll(&fd, 1, 0));
			if (fd.revents & POLLHUP) {
				close(fd.fd);
				lo->mounted_fd = -1;
				if (!lo->c.single)
					lo_start_threads(lo);
			} else if (fd.revents != 0) {
				err(1, "poll: revents: %i", fd.revents);
			}
		}
	}
}
static void lo_start_common(struct lo_thread_data *ltd)
{
	struct lo_data *lo = ltd->lo;
	int devfd = lo->devfd;
	int fd = devfd;

	if (ltd->lo->c.uring) {
		lo_start_uring(ltd);
		return;
	}

	if (ltd->lo->c.bind) {
		fd = ER(open("/dev/fuse", O_RDWR));
		ER(ioctl(fd, FUSE_DEV_IOC_CLONE, &devfd));
	}

	lo_loop(lo, fd);
}

static void *lo_start_one(void *data)
{
	struct lo_thread_data *ltd = data;
	cpu_set_t one;

	CPU_ZERO(&one);
	CPU_SET(ltd->cpu, &one);
	PE(pthread_setaffinity_np(pthread_self(), sizeof(one), &one));

	lo_start_common(ltd);
	return NULL;
}

static int lo_start_one_nt(void *data)
{
	struct lo_thread_data *ltd = data;
	cpu_set_t one;

	CPU_ZERO(&one);
	CPU_SET(ltd->cpu, &one);
	ER(sched_setaffinity(0, sizeof(one), &one));

	lo_start_common(data);
	return 0;
}

static void lo_start_threads(struct lo_data *lo)
{
	int i, n;
	cpu_set_t set;
	struct lo_thread_data *ltd;

	ER(sched_getaffinity(0, sizeof(set), &set));

	n = CPU_COUNT(&set);
	for (i = 0; n && i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &set)) {
			ltd = NL(malloc(sizeof(*ltd)));
			ltd->lo = lo;
			ltd->cpu = i;
			if (!lo_nothread(lo)) {
				pthread_t id;

				PE(pthread_create(&id, NULL, lo_start_one, ltd));
			} else {
				void *stack, *top;
				size_t stack_size = 1048576;

				stack = NL(malloc(stack_size));
				top = stack + stack_size;

				ER(clone(lo_start_one_nt, top, CLONE_FILES, ltd));
			}
			n--;
		}
	}
}

static void lo_mount(struct lo_data *lo)
{
	int fs_fd, mnt_fd;
	int ret;

	if (lo->c.fusex) {
		fs_fd = ER(fsopen("fusex", 0));
		if (lo->c.tag)
			ER(fsconfig(fs_fd, FSCONFIG_SET_STRING, "source", lo->c.tag, 0));
		ER(fsconfig(fs_fd, FSCONFIG_SET_FD, "fd", NULL, lo->devfd));
	} else {
		fs_fd = ER(fsopen("fuse", 0));
		ret = fsconfig(fs_fd, FSCONFIG_SET_FD, "fd", NULL, lo->devfd);
		if (ret == -1) {
			char opt[64];
			snprintf(opt, sizeof(opt), "%i", lo->devfd);
			ER(fsconfig(fs_fd, FSCONFIG_SET_STRING, "fd", opt, 0));
		}
		ER(fsconfig(fs_fd, FSCONFIG_SET_STRING, "rootmode", "40000", 0));
		ER(fsconfig(fs_fd, FSCONFIG_SET_STRING, "user_id", "0", 0));
		ER(fsconfig(fs_fd, FSCONFIG_SET_STRING, "group_id", "0", 0));
	}
	close(lo->devfd);
	ER(fsconfig(fs_fd, FSCONFIG_CMD_CREATE, 0, 0, 0));
	mnt_fd = ER(fsmount(fs_fd, 0, lo->c.mount_flags));
	ER(move_mount(mnt_fd, "", AT_FDCWD, lo->c.mnt, MOVE_MOUNT_F_EMPTY_PATH));
	close(mnt_fd);
	close(fs_fd);
	if (lo->mounted_fd != -1)
		close(lo->mounted_fd);
	_exit(0);
}

struct mount_flags {
    const char *opt;
    unsigned int set;
    unsigned int clear ;
};

static const struct mount_flags mount_flags[] = {
	{"rw",		0,			MOUNT_ATTR_RDONLY},
	{"ro",		MOUNT_ATTR_RDONLY,	0},
	{"suid",	0,			MOUNT_ATTR_NOSUID},
	{"nosuid",	MOUNT_ATTR_NOSUID,	0},
	{"dev",		0,			MOUNT_ATTR_NODEV},
	{"nodev",	MOUNT_ATTR_NODEV,	0},
	{"exec",	0,			MOUNT_ATTR_NOEXEC},
	{"noexec",	MOUNT_ATTR_NOEXEC,	0},
	{"diratime",	0, 			MOUNT_ATTR_NODIRATIME},
	{"nodiratime",	MOUNT_ATTR_NODIRATIME,	0},
	{"symfollow",	0,			MOUNT_ATTR_NOSYMFOLLOW},
	{"nosymfollow",	MOUNT_ATTR_NOSYMFOLLOW,	0},
	{"atime",	0,			MOUNT_ATTR__ATIME},
	{"noatime",	MOUNT_ATTR_NOATIME,	MOUNT_ATTR__ATIME},
	{"relatime",	MOUNT_ATTR_RELATIME,	MOUNT_ATTR__ATIME},
	{"strictatime",	MOUNT_ATTR_STRICTATIME,	MOUNT_ATTR__ATIME},
	{NULL,		0,		0}
};

static void lo_parse_opts(struct lo_config *c, char *opts)
{
	for (char *opt = strtok(opts, ","); opt; opt = strtok(NULL, ",")) {
		const char *source_pfx = "source=";
		size_t source_len = strlen(source_pfx);
		bool found = false;

		if (strncmp(opt, source_pfx, source_len) == 0) {
			c->source = opt + source_len;
			found = true;
		} else {
			for (const struct mount_flags *mf = mount_flags; mf->opt; mf++) {
				if (strcmp(opt, mf->opt) == 0) {
					c->mount_flags &= ~mf->clear;
					c->mount_flags |= mf->set;
					found = true;
					break;
				}
			}
		}
		if (!found)
			errx(1, "unknown mount option: %s", opt);
	}
}

static void lo_usage(char *argv[])
{
	errx(1, "usage: %s [-d] [-s] [-b] [-r] [-t] mountpoint", argv[0]);
}

int main(int argc, char *argv[])
{
	struct lo_data *lo;
	struct lo_config c = {};
	char *devname = "/dev/fuse";
	struct statx stat;
	int ctr;
	bool background = false;
	bool is_child;
	int pip[2];
	int tfds[3];

	if (argc < 2)
		lo_usage(argv);

	c.source = "/";
	c.timeout = 999999;
	for (ctr = 1; ctr < argc; ctr++) {
		char *arg = argv[ctr];

		if (arg[0] == '-') {
			switch (arg[1]) {
			case 'd':
				c.debug = 1;
				break;
			case 's':
				c.single = 1;
				break;
			case 'b':
				c.bind = 1;
				break;

			case 'r':
				c.direct = 1;
				break;
			case 'u':
				c.uring = 1;
				c.queue_depth = 24;
				c.req_size = 1048576;
				break;
			case 'p':
				c.passthrough = 1;
				break;

			case 'q':
				c.passthrough2 = 1;
				break;
#ifdef LO_NOTHREAD
			case 't':
				c.nothread = 1;
				break;
#endif
			case 'x':
				c.fusex = 1;
				c.no_open = 1;
				break;

			case 'o':
				lo_parse_opts(&c, arg+2);
				break;

			case 'c':
				c.tag = arg+2;
 				break;

			case 'z':
				background = true;
				break;

			default:
				lo_usage(argv);
			}

		} else if (!c.mnt) {
			c.mnt = arg;
		} else {
			lo_usage(argv);
		}
	}

	if (c.nothread)
		lo = lo_alloc_lo_nt();
	else
		lo = NL(calloc(1, sizeof(struct lo_data)));

	lo->c = c;
	lo_mutex_init(lo);

	/* Don't mask creation mode, kernel already did that */
	umask(0);

	lo->root.next = lo->root.prev = &lo->root;
	lo->root.refcount = 2;

	lo->root.fd = ER(open(lo->c.source, O_RDONLY));

	ER(statx(lo->root.fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stat));

	lo_convert_stat(&stat, &lo->root.attr);

	lo->devfd = ER(open(devname, O_RDWR));

	ER(ioctl(lo->devfd, FUSE_DEV_IOC_SYNC_INIT));

	if (lo->c.uring) {
		tfds[0] = ER(open("/dev/null", O_RDONLY, 0));
		tfds[1] = ER(dup(tfds[0]));
		tfds[2] = ER(dup(tfds[1]));
		ER(pipe(pip));
		close(tfds[0]);
		close(tfds[1]);
		close(tfds[2]);
	} else {
		lo->mounted_fd = -1;
	}

	is_child = !ER(fork());
	if (background && is_child) {
		int nullfd;

		ER(setsid());
		(void) chdir("/");

		nullfd = ER(open("/dev/null", O_RDWR, 0));
		(void) dup2(nullfd, 0);
		(void) dup2(nullfd, 1);
		(void) dup2(nullfd, 2);
		if (nullfd > 2)
			close(nullfd);
	}

	if (background ^ is_child) {
		if (lo->c.uring) {
			close(pip[0]);
			lo->mounted_fd = pip[1];
		}
		lo_mount(lo);
	}
	if (lo->c.uring) {
		close(pip[1]);
		lo->mounted_fd = pip[0];
	} else if (!lo->c.single)
 		lo_start_threads(lo);

	lo_loop(lo, lo->devfd);

	return 0;
}
