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
	uint64_t timeout;
	const char *source;
	int nothread;
	int direct;
	int uring;
	int queue_depth;
	size_t req_size;
	int passthrough;
	int passthrough2;
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
	int tag;
	struct fuse_ring_req *rreq;
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

#ifdef LO_URING
static void lo_queue_uring(struct lo_req *req, int cmd_op)
{
	struct io_uring_sqe *sqe;
	struct fuse_uring_cmd_req *ureq;

	req->rr.unique = 0; /* request is in waiting state */
	sqe = NL(io_uring_get_sqe(req->rr.ring));
	io_uring_prep_cmd_sock(sqe, cmd_op, 0, 0, 0, NULL, 0);
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	ureq = (struct fuse_uring_cmd_req *) &sqe->cmd[0];
	ureq->buf_ptr = (uint64_t) req->rr.rreq;
	ureq->buf_len = req->lo->c.req_size;
	ureq->qid = req->rr.qid;
	ureq->tag = req->rr.tag;
	ureq->flags = 0;
	io_uring_sqe_set_data(sqe, req);
}

static void lo_reply_uring(struct lo_req *req, int error, size_t argsize)
{
	struct fuse_ring_req *rreq = req->rr.rreq;

	rreq->in_out_arg_len = argsize;
	rreq->out.len = sizeof(struct fuse_out_header) + argsize;
	rreq->out.error = -error;
	rreq->out.unique = req->rr.unique;

	lo_queue_uring(req, FUSE_URING_REQ_COMMIT_AND_FETCH);
	NE(io_uring_submit(req->rr.ring));
}
#endif

static void lo_reply(struct lo_req *req, int error, size_t argsize)
{
	if (lo_debug(req)) {
		fprintf(stderr, "   error: %i, outsize: %zu\n", error,
			sizeof(struct fuse_out_header) + argsize);
	}
#ifdef LO_URING
	if (req->is_ch)
#endif
		lo_reply_ch(req, error, argsize);
#ifdef LO_URING
	else
		lo_reply_uring(req, error, argsize);
#endif
}

static void *lo_out_arg(struct lo_req *req)
{
#ifdef LO_URING
	if (req->is_ch)
#endif
		return ((struct fuse_out_header *) req->ch.outbuf) + 1;
#ifdef LO_URING
	else
		return req->rr.rreq->in_out_arg;
#endif
}

static bool lo_overflow(struct lo_req *req, size_t size)
{
#ifdef LO_URING
	if (req->is_ch)
#endif
		return size > req->ch.bufsize - sizeof(struct fuse_out_header);
#ifdef LO_URING
	else
		return size > req->lo->c.req_size - FUSE_RING_HEADER_BUF_SIZE;
#endif
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
	struct fuse_attr_out *outarg = lo_out_arg(req);

	(void) inarg;

	if (lo_debug(req))
		fprintf(stderr, "lo_getattr(ino=%"PRIu64")\n", inh->nodeid);

	outarg->attr_valid = lo->c.timeout;
	outarg->attr_valid_nsec = 0;
	outarg->dummy = 0;
	outarg->attr = lo_inode(lo, inh->nodeid)->attr;
	lo_reply(req, 0, sizeof(*outarg));
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

#if 0
	/* FIXME: name gets overwritten with fuse_uring */
	if (lo_debug(req)) {
		fprintf(stderr, "  %"PRIu64"/%s -> %"PRIu64"\n",
			inh->nodeid, name, outarg->nodeid);
	}
#endif

	lo_reply(req, 0, sizeof(*outarg));
	return;

out_err:
	saverr = errno;
	if (newfd != -1)
		close(newfd);
	lo_reply(req, saverr, 0);
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

static struct lo_file *lo_file(uint64_t fh)
{
	return (void *) (uintptr_t) fh;
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
	struct lo_file *lf = lo_file(inarg->fh);
	ssize_t res;

	(void) inh;

	if (lo_overflow(req, inarg->size)) {
		lo_reply(req, EOVERFLOW, 0);
		return;
	}

	res = pread(lf->fd, outarg, inarg->size, inarg->offset);
	if (res == -1) {
		lo_reply(req, errno, 0);
		return;
	}

	lo_reply(req, 0, res);
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
			    struct fuse_batch_forget_in *inarg)
{
	struct fuse_forget_one *param = (void *) (inarg + 1);
	unsigned int i;

	(void) inh;

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

	outarg->flags = outflags;
	if (outflags & FUSE_INIT_EXT)
		outarg->flags2 = outflags >> 32;
	outarg->major = FUSE_KERNEL_VERSION;
	outarg->minor = FUSE_KERNEL_MINOR_VERSION;
	outarg->max_readahead = inarg->max_readahead;

	lo_reply(req, 0, sizeof(*outarg));
}

static size_t lo_getreq(struct lo_chan *lc)
{
	ssize_t res;

	res = ER(read(lc->fd, lc->inbuf, lc->bufsize));
	if ((size_t) res < sizeof(struct fuse_in_header))
		errx(1, "short read from fuse device");
	return res;
}

static void lo_process(struct lo_req *req, struct fuse_in_header *inh,
		       void *arg, size_t len, struct io_uring_cqe *cqe)
{

	if (lo_debug(req)) {
		fprintf(stderr,
			"%cunique: %"PRIu64", opcode: %i, nodeid: %"PRIu64", insize: %zu\n",
			req->is_ch ? ' ' : cqe ? '.' : '*',
			inh->unique, inh->opcode, inh->nodeid, len);
	}

	switch (inh->opcode) {
	case FUSE_INIT:
		lo_init(req, inh, arg);
		break;

	case FUSE_LOOKUP:
		lo_lookup(req, inh, arg);
		break;

	case FUSE_GETATTR:
		lo_getattr(req, inh, arg);
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
		lo_batch_forget(req->lo, inh, arg);
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

#ifdef LO_URING
static void lo_start_uring(struct lo_thread_data *ltd)
{
	int fd, tag;
	struct lo_data *lo = ltd->lo;
	struct io_uring ring;
	struct lo_req *req;
	struct fuse_ring_queue_config queue_cfg = {
		.qid = ltd->cpu,
		.control_fd = lo->devfd,
	};

	fd = ER(open("/dev/fuse", O_RDWR));
	ER(ioctl(fd, FUSE_DEV_IOC_URING_QUEUE_CFG, &queue_cfg));
	NE(io_uring_queue_init(lo->c.queue_depth, &ring, IORING_SETUP_SQE128));
	NE(io_uring_register_files(&ring, &fd, 1));

	for (tag = 0; tag < lo->c.queue_depth; tag++) {
		req = NL(calloc(1, sizeof(*req)));
		req->lo = lo;
		req->is_ch = 0;
		req->rr.ring = &ring,
		req->rr.qid = ltd->cpu;
		req->rr.tag = tag;

		PE(posix_memalign((void **) &req->rr.rreq, 0x1000, lo->c.req_size));
		lo_queue_uring(req, FUSE_URING_REQ_FETCH);
	}
	NE(io_uring_submit(&ring));

	for (;;) {
		struct fuse_ring_req *rreq;
		struct io_uring_cqe *cqe;
		int cont = 1;

		NE(io_uring_wait_cqe(&ring, &cqe));

		req = io_uring_cqe_get_data(cqe);
		rreq = req->rr.rreq;
		if (!req->rr.unique) {
			req->rr.unique = rreq->in.unique;
			cont = 0;
		}
		lo_process(req, &rreq->in, rreq->in_out_arg,
			   sizeof(rreq->in) + rreq->in_out_arg_len,
			   cont ? cqe : NULL);
		io_uring_cqe_seen(req->rr.ring, cqe);
	}
}

static void lo_config_uring(struct lo_data *lo)
{
	int nr_queues = get_nprocs_conf();
	struct fuse_ring_config rconf = {
		.nr_queues		= nr_queues,
		.sync_queue_depth	= lo->c.queue_depth / 3 * 2,
		.async_queue_depth	= lo->c.queue_depth - rconf.sync_queue_depth,
		.user_req_buf_sz	= lo->c.req_size,
		.numa_aware		= nr_queues > 1,
	};
	ER(ioctl(lo->devfd, FUSE_DEV_IOC_URING_CFG, &rconf));
}
#endif /* LO_URING */

#if 0
static void *lo_process_init(void *data)
{
	struct lo_data *lo = data;
	struct lo_req req = {
		.lo = lo,
		.is_ch = 1,
		.ch.fd = lo->devfd,
	};
	struct fuse_in_header *inh;
	void *arg;
	size_t len;

	lo_alloc_bufs(&req.ch);
	inh = req.ch.inbuf;
	arg = inh + 1;
	len = lo_getreq(&req.ch);
	lo_process(&req, inh, arg, len, NULL);

	return NULL;
}
#endif

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
		lo_process(&req, inh, arg, len, NULL);
	}

}

static void lo_start_common(struct lo_thread_data *ltd)
{
	struct lo_data *lo = ltd->lo;
	int devfd = lo->devfd;
	int fd = devfd;

#ifdef LO_URING
	if (ltd->lo->c.uring) {
		lo_start_uring(ltd);
		return;
	}
#endif

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

static void lo_usage(char *argv[])
{
	errx(1, "usage: %s [-d] [-s] [-b] [-r] [-t] mountpoint", argv[0]);
}

int main(int argc, char *argv[])
{
	struct lo_data *lo;
	struct lo_config c = {};
	char *devname = "/dev/fuse";
	char opts[128];
	struct statx stat;
	int ctr;
	const char *mnt = NULL;
	int delay_threads = 0;

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
#ifdef LO_URING
			case 'u':
				c.uring = 1;
				c.queue_depth = 24;
				c.req_size = 1048576;
				break;
#endif
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
			default:
				lo_usage(argv);
			}

		} else if (!mnt) {
			mnt = arg;
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

	lo->root.fd = ER(open(lo->c.source, O_PATH));

	ER(statx(lo->root.fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stat));

	lo_convert_stat(&stat, &lo->root.attr);

	lo->devfd = ER(open(devname, O_RDWR));

	snprintf(opts, sizeof(opts),
		 "fd=%i,rootmode=40000,user_id=0,group_id=0",
		 lo->devfd);
#ifdef LO_URING
	if (lo->c.uring)
		lo_config_uring(lo);
#endif
	if (!lo->c.single) {
		if (ioctl(lo->devfd, FUSE_DEV_IOC_SYNC_INIT) == 0)
			lo_start_threads(lo);
		else
			delay_threads = 1;
	}

	ER(mount("loraw", mnt, "fuse.loraw", 0, opts));

	if (delay_threads)
		lo_start_threads(lo);

	lo_loop(lo, lo->devfd);

	return 0;
}
