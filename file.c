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
#include <linux/kernel.h>
#define PAGE_SIZES 4096
#define MAX_VERSIONS 5

#define DELETE 12340 
#define LIST 12345
#define RESTORE 12346
#define VIEW 12349

int (*filldir_lowerlevel)(struct dir_context *ctx, const char *arg1, int arg2,
			  loff_t arg3, u64 arg4, unsigned int arg5);

const char *max_version = "user.maximum_bkp_version";
const char *min_version = "user.minimum_bkp_version";
static ssize_t bkpfs_read(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = bkpfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static void make_backup_file_name(char *file_name, int version,
				  char *backup_name)
{
	char *buf;

	buf = kmalloc(11, GFP_KERNEL);
	strcpy(backup_name, file_name);
	strcat(backup_name, ".tmp.");
	sprintf(buf, "%d", version);
	strcat(backup_name, buf);
	kfree(buf);
}

static int backup_file_remove(struct dentry *dentry, int version)
{
	int err = 0;
	struct dentry *parent;
	struct path lower_parent_path;
	struct dentry *lower_dir_dentry = NULL;
	struct vfsmount *lower_dir_mnt;
	struct path lower_path;
	char *backup_name;
	struct dentry *lower_parent_dentry = NULL;

	backup_name = kmalloc(16 +  strlen((char *)dentry->d_name.name),
			      GFP_KERNEL);
	make_backup_file_name((char *)dentry->d_name.name, version,
			      backup_name);
	parent = dget_parent(dentry);
	bkpfs_get_lower_path(parent, &lower_parent_path);
	lower_dir_dentry = lower_parent_path.dentry;
	lower_dir_mnt = lower_parent_path.mnt;
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, backup_name, 0,
			      &lower_path);
	if (err)
		goto out;
	lower_parent_dentry = lock_parent(lower_path.dentry);
	vfs_unlink(lower_dir_dentry->d_inode, lower_path.dentry, NULL);
	unlock_dir(lower_parent_dentry);
out:
	dput(parent);
	kfree(backup_name);
	return err;
}

static ssize_t backup_file_create(struct dentry *dentry)
{
	long bytes_written = 0;
	int err = 0;
	struct dentry *lower_dir_dentry = NULL;
	struct qstr this;
	struct path lower_parent_path;
	struct dentry *parent;
	struct path lower_path;
	struct path another_path;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	struct file *out_file;
	struct file *in_file;
	umode_t mode;
	loff_t file_size = 0;
	int read_offset = 0;
	int write_offset = 0;
	int rem = 0;
	int copy_bytes = 0;
	int max_version_val = 0;
	int min_version_val = 0;
	char *backup_name;

	mode = dentry->d_inode->i_mode;
	backup_name = kmalloc(16 +  strlen((char *)dentry->d_name.name),
			      GFP_KERNEL);
	err = vfs_getxattr(dentry, max_version,
			   (void *)&max_version_val, sizeof(int));
	if (vfs_getxattr(dentry, max_version,
			 (void *)&max_version_val, sizeof(int)) > 0) {
		if (vfs_getxattr(dentry, min_version,
				 (void *)&min_version_val, sizeof(int)) < 0) {
			goto out;
		}
		if (max_version_val - min_version_val >=
		    ((struct bkpfs_sb_info *)dentry->d_sb->s_fs_info)->max_ver - 1) {
			backup_file_remove(dentry, min_version_val++);
			vfs_setxattr(dentry, min_version,
				     (void *)&min_version_val, sizeof(int), 0);
		}
		if (!min_version_val) {
			min_version_val++;
			vfs_setxattr(dentry, min_version,
				     (void *)&min_version_val, sizeof(int), 0);
		}
		max_version_val++;
		make_backup_file_name((char *)dentry->d_name.name,
				      max_version_val, backup_name);
	} else {
		return err;
	}
	/* Creating Negative Dentry start */
	//fill the file using dentry of the current written file
	parent = dget_parent(dentry);
	bkpfs_get_lower_path(parent, &lower_parent_path);
	lower_dir_dentry = lower_parent_path.dentry;
	lower_dir_mnt = lower_parent_path.mnt;
	this.name = backup_name;
	this.len = strlen(backup_name);
	this.hash = full_name_hash(lower_dir_dentry, this.name, this.len);
	lower_dentry = d_lookup(lower_dir_dentry, &this);
	if (lower_dentry)
		goto setup_lower;
	lower_dentry = d_alloc(lower_dir_dentry, &this);
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}
	d_add(lower_dentry, NULL); /* instantiate and hash */
setup_lower:
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_dir_mnt);
	lower_parent_dentry = lock_parent(lower_dentry);
	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one. S_IRWXU
	 */
	if (err == -ENOENT)
		err = 0;
	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 true);
	/* Creating Negative Dentry end */
	unlock_dir(lower_parent_dentry);
	if (err)
		goto out;
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, backup_name, 0,
			      &lower_path);
	out_file = dentry_open(&lower_path, O_WRONLY, current_cred());
	bkpfs_get_lower_path(dentry, &another_path);
	in_file = dentry_open(&another_path, O_RDONLY, current_cred());
	file_size = in_file->f_inode->i_size;
	rem = file_size;
	while (rem > 0) {
		copy_bytes = (rem - PAGE_SIZES > 0) ? PAGE_SIZES : rem;
		bytes_written = vfs_copy_file_range(in_file, read_offset,
						    out_file, write_offset,
						    copy_bytes, 0);
		rem -= copy_bytes;
		read_offset += copy_bytes;
		write_offset += copy_bytes;
	}
out:
	if (in_file)
		filp_close(in_file, NULL);
	if (out_file)
		filp_close(out_file, NULL);
	if (!err)
		vfs_setxattr(dentry, max_version, (void *)&max_version_val,
			     sizeof(int), 0);
	bkpfs_put_lower_path(parent, &lower_parent_path);
	bkpfs_put_lower_path(parent, &lower_path);
	dput(parent);
	kfree(backup_name);
	return err;
}

static ssize_t bkpfs_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	//struct dentry *bkp_dentry;
	lower_file = bkpfs_lower_file(file);
	err  = backup_file_create(dentry);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}
	return err;
}

static int bkpfs_is_filename_pattern_matched(const char *file_name,
					     const char *pattern)
{
	int file_name_len = strlen(file_name);
	int pattern_len = strlen(pattern);
	int i = 0;
	int j = 0;

	if (file_name_len < pattern_len)
		return 0;
	for (i = 0; i < file_name_len - pattern_len + 1; i++) {
		for (j = 0; j < pattern_len; j++) {
			if (file_name[i + j] == pattern[j])
				continue;
			else
				break;
		}
		if (j == pattern_len)
			return 1;
	}
	return 0;
}

static int bkpfs_filldir_toplevel(struct dir_context *ctx, const char *name,
				  int arg1, loff_t arg2, u64 arg3,
				  unsigned int arg4)
{
	if (bkpfs_is_filename_pattern_matched(name, ".tmp."))
		return 0;
	return filldir_lowerlevel(ctx, name, arg1, arg2, arg3, arg4);
}

static int bkpfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = bkpfs_lower_file(file);
	filldir_lowerlevel = ctx->actor;
	ctx->actor = bkpfs_filldir_toplevel;
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

// function returns '0' if version exists for a file
static int check_version_exists(struct file *file, int *max_ver_val,
				int *min_ver_val)
{
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *lower_dentry;
	struct path lower_path;

	bkpfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (vfs_getxattr(lower_dentry, max_version,
			 (void *)max_ver_val, sizeof(int)) > 0) {
		if (vfs_getxattr(lower_dentry, min_version,
				 (void *)min_ver_val, sizeof(int)) > 0)
			return 0;
	}
	return -1;
}

static int backup_files_restore(struct file *file,
				struct dentry *original_dentry,
				unsigned long arg)
{
	char *backup_name;
	struct dentry *original_parent = NULL;
	struct path original_lower_parent_path;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry;
	struct path backup_lower_path;
	struct path original_lower_path;
	struct file *out_file = NULL;
	struct file *in_file = NULL;
	int file_size, rem, copy_bytes, bytes_written, err = 0;
	int read_offset = 0, write_offset = 0;
	int max_ver_val = 0;
	int min_ver_val = 0;
	IOCTL_STRUCT *kaddr = NULL;

	kaddr = kmalloc(sizeof(IOCTL_STRUCT), GFP_KERNEL);
	if (!access_ok(VERIFY_READ, (void *)arg, sizeof(IOCTL_STRUCT))) {
		pr_info("Error in access_ok");
		err = -EFAULT;
		goto out;
	}
	if (copy_from_user((void *)kaddr, (const void *)arg,
			   sizeof(IOCTL_STRUCT))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto out;
	}
//My modifications end
	if (check_version_exists(file, &max_ver_val, &min_ver_val) == -1) {
		pr_info("The version to restore doesn't exist\n");
		err = -EINVAL;
		kfree(kaddr);
		return err;
	}

	if (!access_ok(VERIFY_READ, kaddr->which_version,
		       kaddr->which_version_size)) {
		pr_info("access_ok which version\n");
		err = -EFAULT;
		goto out;
	}
	kaddr->which_version = kmalloc(kaddr->which_version_size + 1,
				       GFP_KERNEL);
	if (copy_from_user(kaddr->which_version,
			   ((IOCTL_STRUCT *)arg)->which_version,
			   kaddr->which_version_size)) {
		pr_info("copy from user at which version\n");
		err = -EFAULT;
		goto out;
	}
	kaddr->which_version[kaddr->which_version_size] = '\0';
	if (!strcmp(kaddr->which_version, "newest")) {//MAX_VERSION
		kaddr->version = max_ver_val;
	} else if (!strcmp(kaddr->which_version, "oldest")) {//MIN_VERSION
		kaddr->version = min_ver_val;
	} else {
		if (kstrtol(kaddr->which_version, 10,
			    (long int *)&kaddr->version)) {
			pr_info("The sent version is not correct\n");
			err = -EINVAL;
			kfree(kaddr->which_version);
			kfree(kaddr);
			return err;
		}
	}
	if (kaddr->version == 0 ||
	    (kaddr->version < min_ver_val && kaddr->version > 0) ||
	    kaddr->version > max_ver_val || min_ver_val == 0) {
		pr_info("The version to restore doesn't exist\n");
		err = -EINVAL;
		kfree(kaddr->which_version);
		kfree(kaddr);
		return err;
	}
	backup_name = kmalloc(16 + strlen(original_dentry->d_name.name)
			      , GFP_KERNEL);
	make_backup_file_name((char *)original_dentry->d_name.name,
			      kaddr->version, backup_name);
	original_parent = dget_parent(original_dentry);
	bkpfs_get_lower_path(original_parent, &original_lower_parent_path);
	lower_dir_dentry = original_lower_parent_path.dentry;
	lower_dir_mnt = original_lower_parent_path.mnt;
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt,
			      backup_name, 0, &backup_lower_path);
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt,
			      (char *)original_dentry->d_name.name, 0,
			      &original_lower_path);
	out_file = dentry_open(&original_lower_path, O_WRONLY | O_TRUNC,
			       current_cred());
	vfs_truncate(&original_lower_path, 0);
	in_file = dentry_open(&backup_lower_path, O_RDONLY, current_cred());
	file_size = in_file->f_inode->i_size;
	rem = file_size;
	while (rem > 0) {
		copy_bytes = (rem - PAGE_SIZES > 0) ? PAGE_SIZES : rem;
		bytes_written = vfs_copy_file_range(in_file, read_offset,
						    out_file, write_offset,
						    copy_bytes, 0);
		if (bytes_written < 0)
			goto out;
		rem -= copy_bytes;
		read_offset += copy_bytes;
		write_offset += copy_bytes;
	}
out:
	if (in_file)
		filp_close(in_file, NULL);
	if (out_file)
		filp_close(out_file, NULL);
	dput(original_parent);
	bkpfs_put_lower_path(original_dentry, &original_lower_path);
	return 0;
}

static int backup_files_list(struct file *file, unsigned long arg)
{
	int err = 0;
	int max_ver_val = 0;
	int min_ver_val = 0;
	int pos = 0;
	int flag = 0;
	struct dentry *dentry = file->f_path.dentry;
	IOCTL_STRUCT *kaddr = NULL;
	char *backup_file;

	kaddr = kmalloc(sizeof(IOCTL_STRUCT), GFP_KERNEL);
	if (!access_ok(VERIFY_READ, (void *)arg, sizeof(IOCTL_STRUCT))) {
		pr_info("Error in access_ok");
		err = -EFAULT;
		goto end;
	}
	if (copy_from_user((void *)kaddr, (const void *)arg,
			   sizeof(IOCTL_STRUCT))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto end;
	}
	if (copy_from_user(&flag, ((IOCTL_STRUCT *)arg)->flag, sizeof(int))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto end;
	}
	if (copy_from_user(&pos, ((IOCTL_STRUCT *)arg)->off_set, sizeof(int))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto end;
	}
	if (!check_version_exists(file, &max_ver_val, &min_ver_val)) {
		if (flag == 2) {
			backup_file = kmalloc(16 +
					      strlen(dentry->d_name.name),
					      GFP_KERNEL);
			pos = min_ver_val;
			flag--;
			if (copy_to_user(kaddr->off_set, &pos, sizeof(int))) {
				pr_info("Error in copy to user Here\n");
				err = -EFAULT;
				goto end;
			}
			if (copy_to_user(kaddr->flag, &flag, sizeof(int))) {
				pr_info("Error in copy to user at flag\n");
				err = -EFAULT;
				goto end;
			}
		} else if (flag == 1) {
			backup_file = kmalloc(16 +
					      strlen(dentry->d_name.name),
					      GFP_KERNEL);
			make_backup_file_name((char *)dentry->d_name.name,
					      pos, backup_file);
			pr_info("The backup file is : %s\n", backup_file);
			pos++;
			if (copy_to_user(kaddr->backup_file,
					 backup_file, strlen(backup_file))) {
				pr_info("Error in copy to user Here\n");
				err = -EFAULT;
				goto end;
			}
			if (copy_to_user(kaddr->off_set, &pos, sizeof(int))) {
				pr_info("Error in copy to user at pos\n");
				err = -EFAULT;
				goto end;
			}
		}
		if (pos == max_ver_val + 1) {
			flag--;
			if (copy_to_user(kaddr->flag, &flag, sizeof(int))) {
				pr_info("Error in copy to user at flag\n");
				err = -EFAULT;
				goto end;
			}
		}
	} else {
		kfree(kaddr);
		return -ENOENT;
	}
end:
	kfree(backup_file);
	kfree(kaddr);
	return err;
}

static int backup_files_view(struct file *file, unsigned long arg)
{
	int err = 0;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *original_parent;
	struct path original_lower_parent_path;
	struct path backup_lower_path;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry;
	struct file *in_file = NULL;
	char *user_buffer = NULL;
	int read = 0;
	int flag = 0;
	loff_t pos = 0;
	int min_ver_val = 0;
	int max_ver_val = 0;
	IOCTL_STRUCT *kaddr = NULL;

	kaddr = kmalloc(sizeof(IOCTL_STRUCT), GFP_KERNEL);

	user_buffer = kmalloc(PAGE_SIZES + 1, GFP_KERNEL);
	if (!access_ok(VERIFY_READ, (void *)arg, sizeof(IOCTL_STRUCT))) {
		pr_info("Error in access_ok");
		err = -EFAULT;
		goto end;
	}
	if (copy_from_user((void *)kaddr, (const void *)arg,
			   sizeof(IOCTL_STRUCT))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto end;
	}
	if (copy_from_user(&flag, ((IOCTL_STRUCT *)arg)->flag, sizeof(int))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto end;
	}
	if (copy_from_user(&pos, ((IOCTL_STRUCT *)arg)->off_set, sizeof(int))) {
		pr_info("Error in copying kaddr");
		err = -EFAULT;
		goto end;
	}
	if (!access_ok(VERIFY_READ, kaddr->which_version,
		       kaddr->which_version_size)) {
		pr_info("access_ok which version\n");
		err = -EFAULT;
		goto end;
	}
	kaddr->which_version = kmalloc(kaddr->which_version_size + 1,
				       GFP_KERNEL);
	if (copy_from_user(kaddr->which_version,
			   ((IOCTL_STRUCT *)arg)->which_version,
			   kaddr->which_version_size)) {
		pr_info("copy from user at which version\n");
		err = -EFAULT;
		goto end;
	}
	kaddr->which_version[kaddr->which_version_size] = '\0';
	kaddr->backup_file = kmalloc(16 +  strlen((char *)dentry->d_name.name)
				      , GFP_KERNEL);
	if (check_version_exists(file, &max_ver_val, &min_ver_val) == -1) {
		pr_info("The files doesn't have backup versions\n");
		err = -EINVAL;
		goto end;
	}
	if (min_ver_val == 0 || max_ver_val == 0) {
		pr_info("The file doesn't have backup versions\n");
		err = -EINVAL;
		goto end;
	}
	if (!strcmp(kaddr->which_version, "newest")) {  //MAX_VERSION
		kaddr->version = max_ver_val;
	} else if (!strcmp(kaddr->which_version, "oldest")) {//MIN_VERSION
		kaddr->version = min_ver_val;
	} else {
		if (kstrtol(kaddr->which_version, 10,
			    (long int *)&kaddr->version)) {
			pr_info("The sent version is not correct\n");
			err = -EINVAL;
			kfree(kaddr->which_version);
			kfree(kaddr->backup_file);
			kfree(kaddr);
			return err;
		}
	}
	if (kaddr->version > max_ver_val || kaddr->version < min_ver_val) {
		pr_info("The backup file version doesn't exist\n");
		err = -EINVAL;
		goto end;
	}
	make_backup_file_name((char *)dentry->d_name.name,
			      kaddr->version, kaddr->backup_file);
	pr_info("The backup file is %s\n", kaddr->backup_file);

	original_parent = dget_parent(dentry);
	bkpfs_get_lower_path(original_parent, &original_lower_parent_path);
	lower_dir_dentry = original_lower_parent_path.dentry;
	lower_dir_mnt = original_lower_parent_path.mnt;
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt,
			      kaddr->backup_file, 0, &backup_lower_path);

	in_file = dentry_open(&backup_lower_path, O_RDONLY, current_cred());

	read = kernel_read(in_file, user_buffer, PAGE_SIZES, &pos);
	user_buffer[read] = '\0';
	if (read < PAGE_SIZES)
		flag = 0;
	if (copy_to_user(kaddr->user_buffer, user_buffer, read + 1)) {
		pr_info("Error in copy to user Here\n");
		err = -EFAULT;
		goto end;
	}
	if (copy_to_user(kaddr->flag, &flag, sizeof(int))) {
		pr_info("Error in copy to user Here\n");
		err = -EFAULT;
		goto end;
	}
	if (copy_to_user(kaddr->off_set, &pos, sizeof(int))) {
		pr_info("Error in copy to user Here\n");
		err = -EFAULT;
		goto end;
	}
end:
	if (err) {
		flag = 0;
		if (copy_to_user(kaddr->flag, &flag, sizeof(int))) {
			pr_info("Error in copy to user Here\n");
			err = -EFAULT;
		}
	}
	kfree(kaddr->which_version);
	kfree(kaddr->backup_file);
	kfree(user_buffer);
	kfree(kaddr);
	if (in_file)
		filp_close(in_file, NULL);
	return err;
}

static long backup_files_delete(struct file *file, struct dentry *dentry,
				unsigned long arg, unsigned int cmd)
{
	int ret = 0;
	int i = 0;
	int min_ver_val = 0;
	int max_ver_val = 0;
	int which_version = 0;
	IOCTL_STRUCT *kaddr = NULL;

	kaddr = kmalloc(sizeof(IOCTL_STRUCT), GFP_KERNEL);
	if (check_version_exists(file,
				 &max_ver_val, &min_ver_val) == -1) {
		ret = -1;
		pr_info("The value of return is %d\n", ret);
		goto out;
	}
	if (!access_ok(VERIFY_READ, (void *)arg, sizeof(IOCTL_STRUCT))) {
		pr_info("Error in access_ok");
		ret = -EFAULT;
		goto out;
	}
	if (copy_from_user((void *)kaddr, (const void *)arg,
			   sizeof(IOCTL_STRUCT))) {
		pr_info("Error in copying kaddr");
		ret = -EFAULT;
		goto out;
	}
	if (!access_ok(VERIFY_READ, kaddr->which_version,
		       kaddr->which_version_size)) {
		pr_info("access_ok which version\n");
		ret = -EFAULT;
		goto out;
	}
	kaddr->which_version = kmalloc(kaddr->which_version_size + 1,
				       GFP_KERNEL);
	if (copy_from_user(kaddr->which_version,
			   ((IOCTL_STRUCT *)arg)->which_version,
			   kaddr->which_version_size)) {
		pr_info("copy from user at which version\n");
		ret = -EFAULT;
		goto out;
	}
	pr_info("The value of string is %s %d\n", kaddr->which_version,
		kaddr->which_version_size);
	kaddr->which_version[kaddr->which_version_size] = '\0';
	if (!strcmp(kaddr->which_version, "oldest")) {
		which_version = 0;
	} else if (!strcmp(kaddr->which_version, "newest")) {
		which_version = 1;
	} else if (!strcmp(kaddr->which_version, "all")) {
		which_version = 2;
	} else {
		pr_info("Version mentioned is not available\n");
		ret = -EINVAL;
		goto out;
	}
	if (which_version == 0) {
		ret = backup_file_remove(dentry, min_ver_val);
	} else if (which_version == 1) {
		ret = backup_file_remove(dentry, max_ver_val);
	} else if (which_version == 2) {
		for (i = min_ver_val; i <= max_ver_val; i++)
			ret = backup_file_remove(dentry, i);
	}
	if (!ret && !which_version && cmd == DELETE) {
		min_ver_val++;
		vfs_setxattr(dentry, min_version, (void *)&min_ver_val,
			     sizeof(int), 0);
	} else if (!ret && which_version == 1 && cmd == DELETE) {
		max_ver_val--;
		vfs_setxattr(dentry, max_version, (void *)&max_ver_val,
			     sizeof(int), 0);
	}
	if ((min_ver_val > max_ver_val && cmd == DELETE) ||
	    (which_version == 2 && cmd == DELETE)) {
		max_ver_val = 0;
		min_ver_val = 0;
		vfs_setxattr(dentry, max_version, (void *)&max_ver_val,
			     sizeof(int), 0);
		vfs_setxattr(dentry, min_version, (void *)&min_ver_val,
			     sizeof(int), 0);
	}
out:
	//if (kaddr->which_version)
	kfree(kaddr->which_version);
	//if (kaddr)
	kfree(kaddr);
	return ret;
}

static long bkpfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	long err = 0;
	struct file *lower_file;
	int max_ver_val = 0;
	int min_ver_val = 0;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *lower_dentry;
	struct path lower_path;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry;
	struct dentry *parent;
	struct path lower_parent_path;

	lower_file = bkpfs_lower_file(file);
	parent = dget_parent(dentry);
	bkpfs_get_lower_path(parent, &lower_parent_path);
	lower_dir_dentry = lower_parent_path.dentry;
	lower_dir_mnt = lower_parent_path.mnt;
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt,
			      dentry->d_name.name, 0, &lower_path);
	lower_dentry = lower_path.dentry;
	switch (cmd) {
	case LIST:
		if (check_version_exists(file,
					 &max_ver_val, &min_ver_val)
					 == -1) {
			err = -1;
			goto out1;
		}
		err = backup_files_list(file, arg);
		break;
	case DELETE:
		if (check_version_exists(file,
					 &max_ver_val, &min_ver_val)
					 == -1) {
			//pr_info("Reaching here\n");
			err = -1;
			goto out1;
		}
		err = backup_files_delete(file, dentry, arg, cmd);
		break;
	case RESTORE:
		err = backup_files_restore(file, dentry, arg);
		break;
	case VIEW:
		err = backup_files_view(file, arg);
		break;
	default:
		err = -1;
		pr_info("Options passed are not correct\n");
		goto out1;
	}

out1:
	/* XXX: use vfs_ioctl if/when VFS exports it 
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	// some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) 
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
	*/
	return err;
}

#ifdef CONFIG_COMPAT
static long bkpfs_compat_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = bkpfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int bkpfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;
	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = bkpfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "bkpfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!BKPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "bkpfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &bkpfs_vm_ops;

	file->f_mapping->a_ops = &bkpfs_aops; /* set our aops */
	if (!BKPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		BKPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int bkpfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct bkpfs_file_info), GFP_KERNEL);
	if (!BKPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link bkpfs's file struct to lower's */
	bkpfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = bkpfs_lower_file(file);
		if (lower_file) {
			bkpfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		bkpfs_set_lower_file(file, lower_file);
	}
	if (err)
		kfree(BKPFS_F(file));
	else
		fsstack_copy_attr_all(inode, bkpfs_lower_inode(inode));
out_err:
	return err;
}

static int bkpfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = bkpfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}
	return err;
}

/* release all lower object references & free the file info structure */
static int bkpfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = bkpfs_lower_file(file);
	if (lower_file) {
		bkpfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(BKPFS_F(file));
	return 0;
}

static int bkpfs_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = bkpfs_lower_file(file);
	bkpfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	bkpfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int bkpfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = bkpfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);
	return err;
}

/*
 * Bkpfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t bkpfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = bkpfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Bkpfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
bkpfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = bkpfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Bkpfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
bkpfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = bkpfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations bkpfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= bkpfs_read,
	.write		= bkpfs_write,
	.unlocked_ioctl	= bkpfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bkpfs_compat_ioctl,
#endif
	.mmap		= bkpfs_mmap,
	.open		= bkpfs_open,
	.flush		= bkpfs_flush,
	.release	= bkpfs_file_release,
	.fsync		= bkpfs_fsync,
	.fasync		= bkpfs_fasync,
	.read_iter	= bkpfs_read_iter,
	.write_iter	= bkpfs_write_iter,
};

/* trimmed directory options */
const struct file_operations bkpfs_dir_fops = {
	.llseek		= bkpfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= bkpfs_readdir,
	.unlocked_ioctl	= bkpfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bkpfs_compat_ioctl,
#endif
	.open		= bkpfs_open,
	.release	= bkpfs_file_release,
	.flush		= bkpfs_flush,
	.fsync		= bkpfs_fsync,
	.fasync		= bkpfs_fasync,
};
