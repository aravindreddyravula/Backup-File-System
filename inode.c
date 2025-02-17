/*
 * Copyright (c) 1998-2017 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2017 Stony Brook University
 * Copyright (c) 2003-2017 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "bkpfs.h"

static int bkpfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	const char *max_version = "user.maximum_bkp_version";
	const char *min_version = "user.minimum_bkp_version";
	int max_min_init  = 0;

	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = bkpfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, bkpfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* Setting versioning attributes start */
	if (vfs_getxattr(lower_dentry, max_version, (void *)&max_min_init, sizeof(int)))
	{
		err = vfs_setxattr(lower_dentry, max_version, (void *)&max_min_init, sizeof(int), 0);
		if (err)
			goto out;
		printk("Setting max version number %d\n", err);
	}
	if (vfs_getxattr(lower_dentry, min_version, (void *)&max_min_init, sizeof(int)))
	{
		err = vfs_setxattr(lower_dentry, min_version, (void *)&max_min_init, sizeof(int), 0);
		if (err)
			goto out;
		printk("Setting min version number %d\n", err);
	}
	/* Setting versioning attributes end */
out:
	unlock_dir(lower_parent_dentry);
	bkpfs_put_lower_path(dentry, &lower_path);	
	return err;
}

static int bkpfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;
	file_size_save = i_size_read(d_inode(old_dentry));
	bkpfs_get_lower_path(old_dentry, &lower_old_path);
	bkpfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = bkpfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  bkpfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	bkpfs_put_lower_path(old_dentry, &lower_old_path);
	bkpfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int bkpfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = bkpfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  bkpfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int bkpfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = bkpfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, bkpfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int bkpfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = bkpfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, bkpfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, bkpfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int bkpfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int bkpfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = bkpfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, bkpfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in bkpfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int bkpfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;
	if (flags)
		return -EINVAL;

	bkpfs_get_lower_path(old_dentry, &lower_old_path);
	bkpfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	bkpfs_put_lower_path(old_dentry, &lower_old_path);
	bkpfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int bkpfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *bkpfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;
	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = bkpfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int bkpfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;
	lower_inode = bkpfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int bkpfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = setattr_prepare(dentry, ia);
	if (err)
		goto out_err;

	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = bkpfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = bkpfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	bkpfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int bkpfs_getattr(const struct path *path, struct kstat *stat, 
                          u32 request_mask, unsigned int flags)
{
	int err;
        struct dentry *dentry = path->dentry;
	struct kstat lower_stat;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat, request_mask, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
bkpfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
		const void *value, size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
bkpfs_getxattr(struct dentry *dentry, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = bkpfs_lower_inode(inode);
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
bkpfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
bkpfs_removexattr(struct dentry *dentry, struct inode *inode, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;
	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = bkpfs_lower_inode(inode);
	if (!(lower_inode->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry), lower_inode);
out:
	bkpfs_put_lower_path(dentry, &lower_path);
	return err;
}

const struct inode_operations bkpfs_symlink_iops = {
	.readlink	= bkpfs_readlink,
	.permission	= bkpfs_permission,
	.setattr	= bkpfs_setattr,
	.getattr	= bkpfs_getattr,
	.get_link	= bkpfs_get_link,
	.listxattr	= bkpfs_listxattr,
};

const struct inode_operations bkpfs_dir_iops = {
	.create		= bkpfs_create,
	.lookup		= bkpfs_lookup,
	.link		= bkpfs_link,
	.unlink		= bkpfs_unlink,
	.symlink	= bkpfs_symlink,
	.mkdir		= bkpfs_mkdir,
	.rmdir		= bkpfs_rmdir,
	.mknod		= bkpfs_mknod,
	.rename		= bkpfs_rename,
	.permission	= bkpfs_permission,
	.setattr	= bkpfs_setattr,
	.getattr	= bkpfs_getattr,
	.listxattr	= bkpfs_listxattr,
};

const struct inode_operations bkpfs_main_iops = {
	.permission	= bkpfs_permission,
	.setattr	= bkpfs_setattr,
	.getattr	= bkpfs_getattr,
	.listxattr	= bkpfs_listxattr,
};

static int bkpfs_xattr_get(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, void *buffer, size_t size)
{
	return bkpfs_getxattr(dentry, inode, name, buffer, size);
}

static int bkpfs_xattr_set(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, const void *value, size_t size,
			    int flags)
{
	if (value)
		return bkpfs_setxattr(dentry, inode, name, value, size, flags);

	BUG_ON(flags != XATTR_REPLACE);
	return bkpfs_removexattr(dentry, inode, name);
}

const struct xattr_handler bkpfs_xattr_handler = {
	.prefix = "",		/* match anything */
	.get = bkpfs_xattr_get,
	.set = bkpfs_xattr_set,
};

const struct xattr_handler *bkpfs_xattr_handlers[] = {
	&bkpfs_xattr_handler,
	NULL
};
