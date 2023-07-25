// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

// 判断参数filename是否为root文件
static bool is_su(const char __user *filename)
{
	static const char su_path[] = "/system/bin/su";
	char ufn[sizeof(su_path)];

	return likely(!co py_from_user(ufn, filename, sizeof(ufn))) &&
	       unlikely(!memcmp(ufn, su_path, sizeof(ufn)));
}

// 在用户空间分配一个栈空间
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static long(*old_newfstatat)(int dfd, const char __user *filename,
			     struct stat *statbuf, int flag);
static long new_newfstatat(int dfd, const char __user *filename,
			   struct stat __user *statbuf, int flag)
{
	struct cred *cred;
	if (!is_su(filename))
		return old_newfstatat(dfd, filename, statbuf, flag);
	cred = (struct cred *)__task_cred(current);
	if(likely(cred->uid.val == 2000) || likely(cred->uid.val == 0))
		return old_newfstatat(dfd, sh_user_path(), statbuf, flag);
	return old_newfstatat(dfd, filename, statbuf, flag);
}

static long(*old_faccessat)(int dfd, const char __user *filename, int mode);
static long new_faccessat(int dfd, const char __user *filename, int mode)
{
	struct cred *cred;
	if (!is_su(filename))
		return old_faccessat(dfd, filename, mode);
	cred = (struct cred *)__task_cred(current);
	if(likely(cred->uid.val == 2000) || likely(cred->uid.val == 0))
		return old_faccessat(dfd, sh_user_path(), mode);
	return old_faccessat(dfd, filename, mode);
}


extern int selinux_enforcing;
static long (*old_execve)(const char __user *filename,
			  const char __user *const __user *argv,
			  const char __user *const __user *envp);
static long new_execve(const char __user *filename,
		       const char __user *const __user *argv,
		       const char __user *const __user *envp)
{
	static const char now_root[] = "You are now root.\n";
	struct cred *cred;

	if (!is_su(filename))
		return old_execve(filename, argv, envp);

	if (!old_execve(filename, argv, envp))
		return 0;
	// 禁用selinux
	selinux_enforcing = 0;

	// 常规提权
	cred = prepare_kernel_cred(NULL);
	commit_creds(cred);
	
	// 特殊方式提权 避免对任务的密钥环进行操作 以便进行磁盘访问
	// cred = (struct cred *)__task_cred(current);
	// memset(&cred->uid, 0, sizeof(cred->uid));
	// memset(&cred->gid, 0, sizeof(cred->gid));
	// memset(&cred->suid, 0, sizeof(cred->suid));
	// memset(&cred->euid, 0, sizeof(cred->euid));
	// memset(&cred->egid, 0, sizeof(cred->egid));
	// memset(&cred->fsuid, 0, sizeof(cred->fsuid));
	// memset(&cred->fsgid, 0, sizeof(cred->fsgid));
	// memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
	// memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
	// memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
	// memset(&cred->cap_bset, 0xff, sizeof(cred->cap_bset));
	// memset(&cred->cap_ambient, 0xff, sizeof(cred->cap_ambient));

	sys_write(2, userspace_stack_buffer(now_root, sizeof(now_root)),
		  sizeof(now_root) - 1);
	return old_execve(sh_user_path(), argv, envp);
}

extern const unsigned long sys_call_table[];
static void read_syscall(void **ptr, unsigned int syscall)
{
	*ptr = READ_ONCE(*((void **)sys_call_table + syscall));
}
static void replace_syscall(unsigned int syscall, void *ptr)
{
	WRITE_ONCE(*((void **)sys_call_table + syscall), ptr);
}
#define read_and_replace_syscall(name) do { \
	read_syscall((void **)&old_ ## name, __NR_ ## name); \
	replace_syscall(__NR_ ## name, &new_ ## name); \
} while (0)

static int superuser_init(void)
{
	printk("Debug superuser_init\n");
	// 系统调用，用于获取文件的元数据信息。
	read_and_replace_syscall(newfstatat);
	// 系统调用，用于检查指定路径下的文件是否具有指定的访问权限。
	read_and_replace_syscall(faccessat);
	// 系统调用，用于在当前进程中执行一个新的程序
	read_and_replace_syscall(execve);

	return 0;
}

module_init(superuser_init);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Kernel-assisted superuser for Android");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
