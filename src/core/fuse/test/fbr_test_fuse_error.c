/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

// TODO we need an infinite loop error (or thread crash) and a timeout mechanism

#include <string.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

#include "fbr_test_fuse_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"

#define _ERR_FILE_INODE		1234
#define _ERR_DIR_INODE		(_ERR_FILE_INODE + 1)

int _ERR_STATE;
char _ERR_FILENAME[128];

static void
_test_error_CRASH(void)
{
	int *i = (int*)1;
	i--;
	*i = 1;
}

static void
_test_err_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);

	struct fbr_fs *fs = ctx->fs;
	fbr_fs_ok(fs);

	fs->logger = fbr_test_fs_logger;

	if (_ERR_STATE == 1) {
		fbr_test_logs("** INIT doing abort");
		fbr_ABORT("Forced abort")
	} else if (_ERR_STATE == 2) {
		fbr_test_logs("** INIT crashing");
		_test_error_CRASH();
	}

	fbr_test_logs("** INIT success");

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);
	fbr_dindex_release(fs, &root);
}

static void
_fuse_err_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fi;

	fbr_test_logs("** GETATTR ino: %lu", ino);

	if (_ERR_STATE == 3) {
		fbr_test_logs("** GETATTR PRE crashing");
		_test_error_CRASH();
	}

	if (ino == _ERR_FILE_INODE) {
		struct stat st;
		fbr_ZERO(&st);
		st.st_ino = _ERR_FILE_INODE;
		st.st_mode = S_IFREG | 0444;
		fbr_fuse_reply_attr(request, &st, fbr_fs_dentry_ttl(fs));
		return;
	} else if (ino == _ERR_DIR_INODE) {
		struct stat st;
		fbr_ZERO(&st);
		st.st_ino = _ERR_DIR_INODE;
		st.st_mode = S_IFDIR | 0555;
		fbr_fuse_reply_attr(request, &st, fbr_fs_dentry_ttl(fs));
		return;
	}

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_file_ok(file);

	struct stat st;
	fbr_file_attr(file, &st);

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_attr(request, &st, fbr_fs_dentry_ttl(fs));

	if (_ERR_STATE == 4) {
		fbr_test_logs("** GETATTR POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	fbr_request_valid(request);
	(void)parent;

	fbr_test_logs("** LOOKUP '%s'", name);

	if (!strcmp(name, "lookup1")) {
		fbr_test_logs("** LOOKUP PRE crashing");
		_test_error_CRASH();
	}

	if (!strncmp(name, "fiber", 5)) {
		size_t len = strlen(name);
		_ERR_STATE = (name[len - 2] - '0') * 10;
		_ERR_STATE += name[len - 1] - '0';

		snprintf(_ERR_FILENAME, sizeof(_ERR_FILENAME), "%s", name);

		fbr_test_logs("** LOOKUP file _ERR_STATE: %d", _ERR_STATE);
		fbr_test_logs("** LOOKUP filename: '%s'", _ERR_FILENAME);

		struct fuse_entry_param entry;
		fbr_ZERO(&entry);
		entry.ino = _ERR_FILE_INODE;
		entry.attr.st_ino = _ERR_FILE_INODE;
		entry.attr.st_mode = S_IFREG | 0444;
		fbr_fuse_reply_entry(request, &entry);
	} else if (!strncmp(name, "dir", 3)) {
		size_t len = strlen(name);
		if (name[len - 1] == '5') {
			_ERR_STATE = 5;
		} else if (name[len - 1] == '6') {
			_ERR_STATE = 6;
		} else if (name[len - 1] == '7') {
			_ERR_STATE = 7;
		} else if (name[len - 1] == '8') {
			_ERR_STATE = 8;
		} else if (name[len - 1] == '9') {
			_ERR_STATE = 9;
		} else if (name[len - 1] == '0') {
			_ERR_STATE = 10;
		}

		fbr_test_logs("** LOOKUP dir _ERR_STATE: %d", _ERR_STATE);

		struct fuse_entry_param entry;
		fbr_ZERO(&entry);
		entry.ino = _ERR_DIR_INODE;
		entry.attr.st_ino = _ERR_DIR_INODE;
		entry.attr.st_mode = S_IFDIR | 0555;
		fbr_fuse_reply_entry(request, &entry);
	} else {
		fbr_fuse_reply_err(request, ENOENT);
	}

	if (!strcmp(name, "lookup2")) {
		fbr_test_logs("** LOOKUP POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);

	fbr_test_logs("** OPENDIR ino: %lu", ino);

	if (ino != _ERR_DIR_INODE) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	if (_ERR_STATE == 5) {
		fbr_test_logs("** OPENDIR PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_open(request, fi);

	if (_ERR_STATE == 6) {
		fbr_test_logs("** OPENDIR POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	fbr_request_valid(request);
	(void)size;
	(void)off;
	(void)fi;

	fbr_test_logs("** READDIR ino: %lu", ino);

	if (_ERR_STATE == 7) {
		fbr_test_logs("** READDIR PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_buf(request, NULL, 0);

	if (_ERR_STATE == 8) {
		fbr_test_logs("** READDIR POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);
	(void)fi;

	fbr_test_logs("** RELEASEDIR ino: %lu", ino);

	if (_ERR_STATE == 9) {
		fbr_test_logs("** RELEASEDIR PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_err(request, 0);

	if (_ERR_STATE == 10) {
		fbr_test_logs("** RELEASEDIR POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);

	fbr_test_logs("** OPEN ino: %lu", ino);

	if (ino != _ERR_FILE_INODE) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	if (_ERR_STATE == 11) {
		fbr_test_logs("** OPEN PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_open(request, fi);

	if (_ERR_STATE == 12) {
		fbr_test_logs("** OPEN POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	fbr_request_valid(request);
	(void)off;
	(void)size;
	(void)fi;

	fbr_test_logs("** READ ino: %lu", ino);

	if (_ERR_STATE == 13) {
		fbr_test_logs("** READ PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_buf(request, NULL, 0);

	if (_ERR_STATE == 14) {
		fbr_test_logs("** READ POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_write(struct fbr_request *request, fuse_ino_t ino, const char *buf, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	fbr_request_valid(request);
	(void)buf;
	(void)off;
	(void)size;
	(void)fi;

	fbr_test_logs("** WRITE ino: %lu", ino);

	if (_ERR_STATE == 15) {
		fbr_test_logs("** WRITE PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_write(request, 0);

	if (_ERR_STATE == 16) {
		fbr_test_logs("** WRITE PRE crashing");
		_test_error_CRASH();
	}
}


static void
_fuse_err_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);
	(void)fi;

	fbr_test_logs("** FLUSH ino: %lu", ino);

	if (_ERR_STATE == 17) {
		fbr_test_logs("** FLUSH PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_err(request, 0);

	if (_ERR_STATE == 18) {
		fbr_test_logs("** FLUSH POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fi;

	fbr_test_logs("** RELEASE ino: %lu", ino);

	if (_ERR_STATE == 19) {
		fbr_test_logs("** RELEASE PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_err(request, 0);

	if (_ERR_STATE == 20) {
		fbr_test_logs("** RELEASE POST crashing");
		_test_error_CRASH();
	}

	int ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session,
		FBR_INODE_ROOT, _ERR_FILENAME, strlen(_ERR_FILENAME));
	assert_dev(ret != -ENOSYS);
}

static void
_fuse_err_fsync(struct fbr_request *request, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	fbr_request_valid(request);
	(void)datasync;
	(void)fi;

	fbr_test_logs("** FSYNC ino: %lu", ino);

	if (_ERR_STATE == 21) {
		fbr_test_logs("** FSYNC PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_err(request, 0);

	if (_ERR_STATE == 22) {
		fbr_test_logs("** FSYNC POST crashing");
		_test_error_CRASH();
	}
}

static void
_fuse_err_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup)
{
	fbr_request_valid(request);
	(void)nlookup;

	fbr_test_logs("** FORGET ino: %lu", ino);

	if (_ERR_STATE == 23) {
		fbr_test_logs("** FORGET PRE crashing");
		_test_error_CRASH();
	}

	fbr_fuse_reply_none(request);

	if (_ERR_STATE == 24) {
		fbr_test_logs("** FORGET POST crashing");
		_test_error_CRASH();
	}
}

static const struct fbr_fuse_callbacks _TEST_ERROR_CALLBACKS = {
	.init = _test_err_init,

	.getattr = _fuse_err_getattr,
	.lookup = _fuse_err_lookup,

	.opendir = _fuse_err_opendir,
	.readdir = _fuse_err_readdir,
	.releasedir = _fuse_err_releasedir,

	.open = _fuse_err_open,
	.read = _fuse_err_read,
	.write = _fuse_err_write,
	.flush = _fuse_err_flush,
	.release = _fuse_err_release,
	.fsync = _fuse_err_fsync,

	.forget = _fuse_err_forget
};

void
fbr_cmd_fuse_error_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count < 1, "Need to pass in a mount");
	fbr_test_ERROR(cmd->param_count > 2, "Too many params");

	char *mount = cmd->params[0].value;

	if (cmd->param_count > 1) {
		long value = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ERROR(value < 0, "Invalid error param");
		_ERR_STATE = value;
	}

	int ret = fbr_fuse_test_mount(ctx, mount, &_TEST_ERROR_CALLBACKS);
	fbr_test_ERROR(ret, "Fuse error mount failed: %s", mount);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse error mounted: %s", mount);
}
