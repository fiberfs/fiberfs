/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_lowlevel.h"

static void
_fuse_ops_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(ctx->fuse_ops);
	assert(conn);

	fbr_fuse_running(ctx, conn);

	if (ctx->fuse_ops->init) {
		ctx->fuse_ops->init(ctx, conn);
	}
}

static void
_fuse_ops_destroy(void *userdata)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->fuse_ops);

	if (ctx->fuse_ops->destroy) {
		ctx->fuse_ops->destroy(ctx);
	}
}

static void
_fuse_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->lookup) {
		ctx->fuse_ops->lookup(req, parent, name);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->forget) {
		ctx->fuse_ops->forget(req, ino, nlookup);
		return;
	}

	fuse_reply_none(req);
}

static void
_fuse_ops_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->getattr) {
		ctx->fuse_ops->getattr(req, ino, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->setattr) {
		ctx->fuse_ops->setattr(req, ino, attr, to_set, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->readlink) {
		ctx->fuse_ops->readlink(req, ino);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->mknod) {
		ctx->fuse_ops->mknod(req, parent, name, mode, rdev);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->mkdir) {
		ctx->fuse_ops->mkdir(req, parent, name, mode);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->unlink) {
		ctx->fuse_ops->unlink(req, parent, name);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->rmdir) {
		ctx->fuse_ops->rmdir(req, parent, name);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->symlink) {
		ctx->fuse_ops->symlink(req, link, parent, name);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent,
    const char *newname, unsigned int flags)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->rename) {
		ctx->fuse_ops->rename(req, parent, name, newparent, newname, flags);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->link) {
		ctx->fuse_ops->link(req, ino, newparent, newname);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->open) {
		ctx->fuse_ops->open(req, ino, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->read) {
		ctx->fuse_ops->read(req, ino, size, off, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->write) {
		ctx->fuse_ops->write(req, ino, buf, size, off, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->flush) {
		ctx->fuse_ops->flush(req, ino, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->release) {
		ctx->fuse_ops->release(req, ino, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->fsync) {
		ctx->fuse_ops->fsync(req, ino, datasync, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->opendir) {
		ctx->fuse_ops->opendir(req, ino, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->readdir) {
		ctx->fuse_ops->readdir(req, ino, size, off, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->releasedir) {
		ctx->fuse_ops->releasedir(req, ino, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->fsyncdir) {
		ctx->fuse_ops->fsyncdir(req, ino, datasync, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->statfs) {
		ctx->fuse_ops->statfs(req, ino);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value,
    size_t size, int flags)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->setxattr) {
		ctx->fuse_ops->setxattr(req, ino, name, value, size, flags);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
    size_t size)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->getxattr) {
		ctx->fuse_ops->getxattr(req, ino, name, size);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->listxattr) {
		ctx->fuse_ops->listxattr(req, ino, size);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->removexattr) {
		ctx->fuse_ops->removexattr(req, ino, name);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->access) {
		ctx->fuse_ops->access(req, ino, mask);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->create) {
		ctx->fuse_ops->create(req, parent, name, mode, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_getlk(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->getlk) {
		ctx->fuse_ops->getlk(req, ino, fi, lock);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_setlk(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock,
    int sleep)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->setlk) {
		ctx->fuse_ops->setlk(req, ino, fi, lock, sleep);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize, uint64_t idx)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->bmap) {
		ctx->fuse_ops->bmap(req, ino, blocksize, idx);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_ioctl(fuse_req_t req, fuse_ino_t ino, unsigned int cmd, void *arg,
    struct fuse_file_info *fi, unsigned flags, const void *in_buf, size_t in_bufsz,
    size_t out_bufsz)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->ioctl) {
		ctx->fuse_ops->ioctl(req, ino, cmd, arg, fi, flags, in_buf, in_bufsz, out_bufsz);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_poll(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi,
    struct fuse_pollhandle *ph)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->poll) {
		ctx->fuse_ops->poll(req, ino, fi, ph);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *bufv, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->write_buf) {
		ctx->fuse_ops->write_buf(req, ino, bufv, off, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_retrieve_reply(fuse_req_t req, void *cookie, fuse_ino_t ino, off_t offset,
    struct fuse_bufvec *bufv)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->retrieve_reply) {
		ctx->fuse_ops->retrieve_reply(req, cookie, ino, offset, bufv);
		return;
	}

	fuse_reply_none(req);
}

static void
_fuse_ops_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->forget_multi) {
		ctx->fuse_ops->forget_multi(req, count, forgets);
		return;
	}

	fuse_reply_none(req);
}

static void
_fuse_ops_flock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int op)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->flock) {
		ctx->fuse_ops->flock(req, ino, fi, op);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset, off_t length,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->fallocate) {
		ctx->fuse_ops->fallocate(req, ino, mode, offset, length, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->readdirplus) {
		ctx->fuse_ops->readdirplus(req, ino, size, off, fi);
		return;
	}

	(void)fuse_reply_err(req, EIO);
}

static void
_fuse_ops_copy_file_range(fuse_req_t req, fuse_ino_t ino_in, off_t off_in,
    struct fuse_file_info *fi_in, fuse_ino_t ino_out, off_t off_out,
    struct fuse_file_info *fi_out, size_t len, int flags)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->copy_file_range) {
		ctx->fuse_ops->copy_file_range(req, ino_in, off_in, fi_in, ino_out, off_out,
			fi_out, len, flags);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static void
_fuse_ops_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->lseek) {
		ctx->fuse_ops->lseek(req, ino, off, whence, fi);
		return;
	}

	(void)fuse_reply_err(req, ENOSYS);
}

static const struct fuse_lowlevel_ops _FUSE_OPS = {
	.init = _fuse_ops_init,
	.destroy = _fuse_ops_destroy,
	.lookup = _fuse_ops_lookup,
	.forget = _fuse_ops_forget,
	.getattr = _fuse_ops_getattr,
	.setattr = _fuse_ops_setattr,
	.readlink = _fuse_ops_readlink,
	.mknod = _fuse_ops_mknod,
	.mkdir = _fuse_ops_mkdir,
	.unlink = _fuse_ops_unlink,
	.rmdir = _fuse_ops_rmdir,
	.symlink = _fuse_ops_symlink,
	.rename = _fuse_ops_rename,
	.link = _fuse_ops_link,
	.open = _fuse_ops_open,
	.read = _fuse_ops_read,
	.write = _fuse_ops_write,
	.flush = _fuse_ops_flush,
	.release = _fuse_ops_release,
	.fsync = _fuse_ops_fsync,
	.opendir = _fuse_ops_opendir,
	.readdir = _fuse_ops_readdir,
	.releasedir = _fuse_ops_releasedir,
	.fsyncdir = _fuse_ops_fsyncdir,
	.statfs = _fuse_ops_statfs,
	.setxattr = _fuse_ops_setxattr,
	.getxattr = _fuse_ops_getxattr,
	.listxattr = _fuse_ops_listxattr,
	.removexattr = _fuse_ops_removexattr,
	.access = _fuse_ops_access,
	.create = _fuse_ops_create,
	.getlk = _fuse_ops_getlk,
	.setlk = _fuse_ops_setlk,
	.bmap = _fuse_ops_bmap,
	.ioctl = _fuse_ops_ioctl,
	.poll = _fuse_ops_poll,
	.write_buf = _fuse_ops_write_buf,
	.retrieve_reply = _fuse_ops_retrieve_reply,
	.forget_multi = _fuse_ops_forget_multi,
	.flock = _fuse_ops_flock,
	.fallocate = _fuse_ops_fallocate,
	.readdirplus = _fuse_ops_readdirplus,
	.copy_file_range = _fuse_ops_copy_file_range,
	.lseek = _fuse_ops_lseek
};

const struct fuse_lowlevel_ops *FBR_FUSE_OPS = &_FUSE_OPS;
