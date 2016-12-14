#include <linux/abi_spec.h>
#include <linux/abispec.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>

typedef void (*cb_t)(void *ctx, struct type *t, int flags, const void __user *p, int post);

static size_t handle_type(cb_t cb, void *ctx, struct type *t, int flags, const void __user *p);

static u64 read_val(struct type *t, int flags, const void __user *p)
{
	int size;
	u64 v;

	switch (t->kind) {
	case KIND_SCALAR:
		size = t->scalar.size;
		break;
	case KIND_PTR:
		size = sizeof(void *);
		break;
	default:
		BUG();
	}
	if (flags & ABI_ARG) {
		switch (size) {
		case 1:
			return *(u8*)p;
		case 2:
			return *(u16*)p;
		case 4:
			return *(u32*)p;
		case 8:
			return *(u64*)p;
		default:
			BUG();
		}
	}
	v = 0;
	switch (t->scalar.size) {
	case 1:
		get_user(v, (u8 __user*)p);
		return v;
	case 2:
		get_user(v, (u16 __user*)p);
		return v;
	case 4:
		get_user(v, (u32 __user*)p);
		return v;
	case 8:
		get_user(v, (u64 __user*)p);
		return v;
	default:
		BUG();
	}
}

static size_t handle_type(cb_t cb, void *ctx, struct type *t, int flags, const void __user *p)
{
	size_t off;

	cb(ctx, t, flags, p, 0);
	switch (t->kind) {
	case KIND_SCALAR: {
		off = t->scalar.size;
		break;
	}
	case KIND_PTR: {
		const void __user* p1;

		p1 = (const void __user*)read_val(t, flags, p);
		handle_type(cb, ctx, t->ptr.type, 0, p1);
		off = sizeof(void *);
		break;
	}
	case KIND_ARRAY: {
		// TODO: don't know the size...
		// off = handle_array(cb, ctx, t, p);
		break;
	}
	case KIND_STRUCT: {
		int i;
		struct argument *arg;
		struct type *f;

		off = 0;
		for (i = 0; i < ABI_MAX_FIELDS; i++) {
			arg = &t->str.fields[i];
			f = arg->type;
			if (!f)
				break;
			if (i)
				cb(ctx, NULL, 0, NULL, 0);
			off += handle_type(cb, ctx, f, arg->flags, p + off);
		}
		break;
	}
	case KIND_UNION: {
		// TODO: don't know what field is active...
		// off = handle_union(cb, ctx, t, p);
		break;
	}
	case KIND_RESOURCE: {
		struct type *t1;

		for (t1 = t; t1->kind == KIND_RESOURCE; t1 = t1->res.type) {}
		off = handle_type(cb, ctx, t1, flags, p);
		break;
	}
	default:
		BUG();
	}
	cb(ctx, t, flags, p, 1);
	return off;
}

static void handle_syscall(cb_t cb, void *ctx, struct syscall_spec *s, va_list *ap)
{
	int i;
	struct argument *arg;
	struct type *f;
	long v;

	for (i = 0; i < ABI_MAX_ARGS; i++) {
		arg = &s->args[i];
		f = arg->type;
		if (!f)
			break;
		if (i)
			cb(ctx, NULL, 0, NULL, 0);
		v = va_arg(*ap, long);
		handle_type(cb, ctx, f, arg->flags, &v);
	}
}

static void check_retval(struct syscall_spec *s, long retval)
{
	int i;

	if (!IS_ERR_VALUE(retval) || !s->errno[0])
		return;
	for (i = 0; i < ABI_MAX_ERRNO; i++) {
		if (s->errno[i] == -retval)
			return;
	}
	__WARN_printf("syscall %s returned unexpected error %ld",
		s->name, retval);
}

struct check_pre_ctx {
	char buf[1024];
	int pos;
};

static __printf(2, 0)
void check_pre_printf(struct check_pre_ctx *ctx, const char *fmt, ...)
{
	va_list args;

	if (ctx->pos >= sizeof(ctx->buf))
		return;
	va_start(args, fmt);
	ctx->pos += vsnprintf(ctx->buf + ctx->pos, sizeof(ctx->buf) - ctx->pos, fmt, args);
	va_end(args);
}

void check_pre_cb(void *ctx, struct type *t, int flags, const void __user *p, int post)
{
	if (!t) {
		check_pre_printf(ctx, ", ");
		return;
	}

	switch (t->kind) {
	case KIND_SCALAR:
		if (post)
			return;
		check_pre_printf(ctx, "0x%llx", read_val(t, flags, p));
		break;
	case KIND_PTR:
		if (post)
			return;
		check_pre_printf(ctx, "&%p=", (void*)read_val(t, flags, p));
		break;
	case KIND_ARRAY:
		check_pre_printf(ctx, post ? "]" : "[");
		break;
	case KIND_STRUCT:
		check_pre_printf(ctx, post ? "}" : "{");
		break;
	case KIND_UNION:
		check_pre_printf(ctx, post ? "<" : ">");
		break;
	case KIND_RESOURCE:
		break;
	default:
		BUG();
	}
}

static void syscall_init(struct syscall_spec *s)
{
	int i;

	for (i = 0; i < ABI_MAX_ARGS; i++) {
		if (!s->args[i].type)
			break;
		s->args[i].flags = ABI_ARG | ABI_IN;
	}
}

void abispec_check_pre(struct syscall_spec *s, ...)
{
	struct check_pre_ctx ctx;
	va_list ap;

	if (!s->args[1].type)
		return;
	// TODO: should do it in abispec_init, but now we don't know how to enumerate over all syscalls.
	syscall_init(s);
	ctx.pos = 0;
	check_pre_printf(&ctx, "[pid %d] %s(", current->pid, s->name);
	va_start(ap, s);
	handle_syscall(check_pre_cb, &ctx, s, &ap);
	va_end(ap);
	check_pre_printf(&ctx, ")\n");
	pr_err("%s", ctx.buf);
}
EXPORT_SYMBOL_GPL(abispec_check_pre);

void abispec_check_post(struct syscall_spec *s, long retval, ...)
{
	struct check_pre_ctx ctx;
	va_list ap;

	if (!s->args[0].type) // not described yet
		return;
	ctx.pos = 0;
	check_pre_printf(&ctx, "[pid %d] %s(", current->pid, s->name);
	va_start(ap, retval);
	handle_syscall(check_pre_cb, &ctx, s, &ap);
	va_end(ap);
	check_pre_printf(&ctx, ") = %ld\n", retval);
	pr_err("%s", ctx.buf);

	check_retval(s, retval);
}
EXPORT_SYMBOL_GPL(abispec_check_post);

void abispec_init(void)
{
}

#define $(x) {x, #x}

static struct type type_i8 = {
	.kind = KIND_SCALAR,
	.scalar.size = 1,
};

/*
static struct type type_i16 = {
	.kind = KIND_SCALAR,
	.scalar.size = 2,
};
*/

static struct type type_i32 = {
	.kind = KIND_SCALAR,
	.scalar.size = 4,
};

/*
static struct type type_i64 = {
	.kind = KIND_SCALAR,
	.scalar.size = 8,
};
*/

static struct type type_iptr = {
	.kind = KIND_SCALAR,
	.scalar.size = sizeof(void *),
};

static struct type type_array_i8 = {
	.kind = KIND_ARRAY,
	.array.type = &type_i8,
};

static struct type type_ptr_array_i8 = {
	.kind = KIND_PTR,
	.ptr.type = &type_array_i8,
};

static struct type type_pathname = {
	.kind = KIND_RESOURCE,
	.res.res = RES_PATHNAME,
	.res.type = &type_array_i8,
};

static struct type type_ptr_pathname = {
	.kind = KIND_PTR,
	.ptr.type = &type_pathname,
};

static struct type type_fd = {
	.kind = KIND_RESOURCE,
	.res.res = RES_FD,
	.res.type = &type_i32,
};

static struct type type_open_flags = {
	.kind = KIND_SCALAR,
	.scalar.size = 4,
	.scalar.constraint = CONSTRAINT_BITMASK,
	.scalar.bitmask = {$(O_RDONLY), $(O_WRONLY), $(O_RDWR), $(O_APPEND),
		$(FASYNC), $(O_CLOEXEC), $(O_CREAT), $(O_DIRECT), $(O_TRUNC),
		$(O_DIRECTORY), $(O_EXCL), $(O_LARGEFILE), $(O_NOATIME),
		$(O_NOCTTY), $(O_NOFOLLOW), $(O_NONBLOCK), $(O_PATH), $(O_SYNC)},
};

static struct type type_open_mode = {
	.kind = KIND_SCALAR,
	.scalar.size = 4,
	.scalar.constraint = CONSTRAINT_BITMASK,
	.scalar.bitmask = {$(S_IRUSR), $(S_IWUSR), $(S_IXUSR),
		$(S_IRGRP), $(S_IWGRP), $(S_IXGRP),
		$(S_IROTH), $(S_IWOTH), $(S_IXOTH)},
};

struct syscall_spec syscall_spec_open = {
	.name = "open",
	.errno = {EACCES, EDQUOT, EEXIST, EFAULT, EFBIG, EINTR, EINVAL, EISDIR,
		ELOOP, EMFILE, ENAMETOOLONG, ENFILE, ENODEV, ENOENT, ENOMEM,
		ENOSPC, ENOTDIR, ENXIO, EOVERFLOW, EPERM, EROFS, ETXTBSY,
		EWOULDBLOCK},
	.ret = &type_fd,
	.args = {
		{"pathname", &type_ptr_pathname},
		{"flags", &type_open_flags},
		{"mode", &type_open_mode},
	},
};

struct syscall_spec syscall_spec_read = {
	.name = "read",
	.errno = {EAGAIN, EWOULDBLOCK, EBADF, EFAULT, EINTR, EINVAL, EIO, EISDIR},
	.ret = &type_iptr,
	.args = {
		{"fd", &type_fd},
		{"buf", &type_ptr_array_i8},
		{"count", &type_iptr}, // TODO: need to say that this length of buf
	},
};

struct syscall_spec syscall_spec_write = {
	.name = "write",
	.errno = {EAGAIN, EBADF, EDESTADDRREQ, EDQUOT, EFAULT, EFBIG, EINTR, EINVAL, EIO, ENOSPC, EPIPE},
	.ret = &type_iptr,
	.args = {
		{"fd", &type_fd},
		{"buf", &type_ptr_array_i8},
		{"count", &type_iptr}, // TODO: need to say that this length of buf
	},
};

struct syscall_spec syscall_spec_close = {
	.name = "close",
	.errno = {EBADF, EINTR, EIO},
	.args = {
		{"fd", &type_fd},
	},
};

struct syscall_spec syscall_spec_stat = { .name = "stat" };
struct syscall_spec syscall_spec_fstat = { .name = "fstat" };
struct syscall_spec syscall_spec_lstat = { .name = "lstat" };
struct syscall_spec syscall_spec_poll = { .name = "poll" };
struct syscall_spec syscall_spec_lseek = { .name = "lseek" };
struct syscall_spec syscall_spec_mmap = { .name = "mmap" };
struct syscall_spec syscall_spec_mprotect = { .name = "mprotect" };
struct syscall_spec syscall_spec_munmap = { .name = "munmap" };
struct syscall_spec syscall_spec_brk = { .name = "brk" };
struct syscall_spec syscall_spec_rt_sigaction = { .name = "rt_sigaction" };
struct syscall_spec syscall_spec_rt_sigprocmask = { .name = "rt_sigprocmask" };
struct syscall_spec syscall_spec_rt_sigreturn = { .name = "rt_sigreturn" };
struct syscall_spec syscall_spec_ioctl = { .name = "ioctl" };
struct syscall_spec syscall_spec_pread64 = { .name = "pread64" };
struct syscall_spec syscall_spec_pwrite64 = { .name = "pwrite64" };
struct syscall_spec syscall_spec_readv = { .name = "readv" };
struct syscall_spec syscall_spec_writev = { .name = "writev" };
struct syscall_spec syscall_spec_access = { .name = "access" };
struct syscall_spec syscall_spec_pipe = { .name = "pipe" };
struct syscall_spec syscall_spec_select = { .name = "select" };
struct syscall_spec syscall_spec_sched_yield = { .name = "sched_yield" };
struct syscall_spec syscall_spec_mremap = { .name = "mremap" };
struct syscall_spec syscall_spec_msync = { .name = "msync" };
struct syscall_spec syscall_spec_mincore = { .name = "mincore" };
struct syscall_spec syscall_spec_madvise = { .name = "madvise" };
struct syscall_spec syscall_spec_shmget = { .name = "shmget" };
struct syscall_spec syscall_spec_shmat = { .name = "shmat" };
struct syscall_spec syscall_spec_shmctl = { .name = "shmctl" };
struct syscall_spec syscall_spec_dup = { .name = "dup" };
struct syscall_spec syscall_spec_dup2 = { .name = "dup2" };
struct syscall_spec syscall_spec_pause = { .name = "pause" };
struct syscall_spec syscall_spec_nanosleep = { .name = "nanosleep" };
struct syscall_spec syscall_spec_getitimer = { .name = "getitimer" };
struct syscall_spec syscall_spec_alarm = { .name = "alarm" };
struct syscall_spec syscall_spec_setitimer = { .name = "setitimer" };
struct syscall_spec syscall_spec_getpid = { .name = "getpid" };
struct syscall_spec syscall_spec_sendfile = { .name = "sendfile" };
struct syscall_spec syscall_spec_socket = { .name = "socket" };
struct syscall_spec syscall_spec_connect = { .name = "connect" };
struct syscall_spec syscall_spec_accept = { .name = "accept" };
struct syscall_spec syscall_spec_sendto = { .name = "sendto" };
struct syscall_spec syscall_spec_recvfrom = { .name = "recvfrom" };
struct syscall_spec syscall_spec_sendmsg = { .name = "sendmsg" };
struct syscall_spec syscall_spec_recvmsg = { .name = "recvmsg" };
struct syscall_spec syscall_spec_shutdown = { .name = "shutdown" };
struct syscall_spec syscall_spec_bind = { .name = "bind" };
struct syscall_spec syscall_spec_listen = { .name = "listen" };
struct syscall_spec syscall_spec_getsockname = { .name = "getsockname" };
struct syscall_spec syscall_spec_getpeername = { .name = "getpeername" };
struct syscall_spec syscall_spec_socketpair = { .name = "socketpair" };
struct syscall_spec syscall_spec_setsockopt = { .name = "setsockopt" };
struct syscall_spec syscall_spec_getsockopt = { .name = "getsockopt" };
struct syscall_spec syscall_spec_clone = { .name = "clone" };
struct syscall_spec syscall_spec_fork = { .name = "fork" };
struct syscall_spec syscall_spec_vfork = { .name = "vfork" };
struct syscall_spec syscall_spec_execve = { .name = "execve" };
struct syscall_spec syscall_spec_exit = { .name = "exit" };
struct syscall_spec syscall_spec_wait4 = { .name = "wait4" };
struct syscall_spec syscall_spec_kill = { .name = "kill" };
struct syscall_spec syscall_spec_uname = { .name = "uname" };
struct syscall_spec syscall_spec_semget = { .name = "semget" };
struct syscall_spec syscall_spec_semop = { .name = "semop" };
struct syscall_spec syscall_spec_semctl = { .name = "semctl" };
struct syscall_spec syscall_spec_shmdt = { .name = "shmdt" };
struct syscall_spec syscall_spec_msgget = { .name = "msgget" };
struct syscall_spec syscall_spec_msgsnd = { .name = "msgsnd" };
struct syscall_spec syscall_spec_msgrcv = { .name = "msgrcv" };
struct syscall_spec syscall_spec_msgctl = { .name = "msgctl" };
struct syscall_spec syscall_spec_fcntl = { .name = "fcntl" };
struct syscall_spec syscall_spec_flock = { .name = "flock" };
struct syscall_spec syscall_spec_fsync = { .name = "fsync" };
struct syscall_spec syscall_spec_fdatasync = { .name = "fdatasync" };
struct syscall_spec syscall_spec_truncate = { .name = "truncate" };
struct syscall_spec syscall_spec_ftruncate = { .name = "ftruncate" };
struct syscall_spec syscall_spec_getdents = { .name = "getdents" };
struct syscall_spec syscall_spec_getcwd = { .name = "getcwd" };
struct syscall_spec syscall_spec_chdir = { .name = "chdir" };
struct syscall_spec syscall_spec_fchdir = { .name = "fchdir" };
struct syscall_spec syscall_spec_rename = { .name = "rename" };
struct syscall_spec syscall_spec_mkdir = { .name = "mkdir" };
struct syscall_spec syscall_spec_rmdir = { .name = "rmdir" };
struct syscall_spec syscall_spec_creat = { .name = "creat" };
struct syscall_spec syscall_spec_link = { .name = "link" };
struct syscall_spec syscall_spec_unlink = { .name = "unlink" };
struct syscall_spec syscall_spec_symlink = { .name = "symlink" };
struct syscall_spec syscall_spec_readlink = { .name = "readlink" };
struct syscall_spec syscall_spec_chmod = { .name = "chmod" };
struct syscall_spec syscall_spec_fchmod = { .name = "fchmod" };
struct syscall_spec syscall_spec_chown = { .name = "chown" };
struct syscall_spec syscall_spec_fchown = { .name = "fchown" };
struct syscall_spec syscall_spec_lchown = { .name = "lchown" };
struct syscall_spec syscall_spec_umask = { .name = "umask" };
struct syscall_spec syscall_spec_gettimeofday = { .name = "gettimeofday" };
struct syscall_spec syscall_spec_getrlimit = { .name = "getrlimit" };
struct syscall_spec syscall_spec_getrusage = { .name = "getrusage" };
struct syscall_spec syscall_spec_sysinfo = { .name = "sysinfo" };
struct syscall_spec syscall_spec_times = { .name = "times" };
struct syscall_spec syscall_spec_ptrace = { .name = "ptrace" };
struct syscall_spec syscall_spec_getuid = { .name = "getuid" };
struct syscall_spec syscall_spec_syslog = { .name = "syslog" };
struct syscall_spec syscall_spec_getgid = { .name = "getgid" };
struct syscall_spec syscall_spec_setuid = { .name = "setuid" };
struct syscall_spec syscall_spec_setgid = { .name = "setgid" };
struct syscall_spec syscall_spec_geteuid = { .name = "geteuid" };
struct syscall_spec syscall_spec_getegid = { .name = "getegid" };
struct syscall_spec syscall_spec_setpgid = { .name = "setpgid" };
struct syscall_spec syscall_spec_getppid = { .name = "getppid" };
struct syscall_spec syscall_spec_getpgrp = { .name = "getpgrp" };
struct syscall_spec syscall_spec_setsid = { .name = "setsid" };
struct syscall_spec syscall_spec_setreuid = { .name = "setreuid" };
struct syscall_spec syscall_spec_setregid = { .name = "setregid" };
struct syscall_spec syscall_spec_getgroups = { .name = "getgroups" };
struct syscall_spec syscall_spec_setgroups = { .name = "setgroups" };
struct syscall_spec syscall_spec_setresuid = { .name = "setresuid" };
struct syscall_spec syscall_spec_getresuid = { .name = "getresuid" };
struct syscall_spec syscall_spec_setresgid = { .name = "setresgid" };
struct syscall_spec syscall_spec_getresgid = { .name = "getresgid" };
struct syscall_spec syscall_spec_getpgid = { .name = "getpgid" };
struct syscall_spec syscall_spec_setfsuid = { .name = "setfsuid" };
struct syscall_spec syscall_spec_setfsgid = { .name = "setfsgid" };
struct syscall_spec syscall_spec_getsid = { .name = "getsid" };
struct syscall_spec syscall_spec_capget = { .name = "capget" };
struct syscall_spec syscall_spec_capset = { .name = "capset" };
struct syscall_spec syscall_spec_rt_sigpending = { .name = "rt_sigpending" };
struct syscall_spec syscall_spec_rt_sigtimedwait = { .name = "rt_sigtimedwait" };
struct syscall_spec syscall_spec_rt_sigqueueinfo = { .name = "rt_sigqueueinfo" };
struct syscall_spec syscall_spec_rt_sigsuspend = { .name = "rt_sigsuspend" };
struct syscall_spec syscall_spec_sigaltstack = { .name = "sigaltstack" };
struct syscall_spec syscall_spec_utime = { .name = "utime" };
struct syscall_spec syscall_spec_mknod = { .name = "mknod" };
struct syscall_spec syscall_spec_uselib = { .name = "uselib" };
struct syscall_spec syscall_spec_personality = { .name = "personality" };
struct syscall_spec syscall_spec_ustat = { .name = "ustat" };
struct syscall_spec syscall_spec_statfs = { .name = "statfs" };
struct syscall_spec syscall_spec_fstatfs = { .name = "fstatfs" };
struct syscall_spec syscall_spec_sysfs = { .name = "sysfs" };
struct syscall_spec syscall_spec_getpriority = { .name = "getpriority" };
struct syscall_spec syscall_spec_setpriority = { .name = "setpriority" };
struct syscall_spec syscall_spec_sched_setparam = { .name = "sched_setparam" };
struct syscall_spec syscall_spec_sched_getparam = { .name = "sched_getparam" };
struct syscall_spec syscall_spec_sched_setscheduler = { .name = "sched_setscheduler" };
struct syscall_spec syscall_spec_sched_getscheduler = { .name = "sched_getscheduler" };
struct syscall_spec syscall_spec_sched_get_priority_max = { .name = "sched_get_priority_max" };
struct syscall_spec syscall_spec_sched_get_priority_min = { .name = "sched_get_priority_min" };
struct syscall_spec syscall_spec_sched_rr_get_interval = { .name = "sched_rr_get_interval" };
struct syscall_spec syscall_spec_mlock = { .name = "mlock" };
struct syscall_spec syscall_spec_munlock = { .name = "munlock" };
struct syscall_spec syscall_spec_mlockall = { .name = "mlockall" };
struct syscall_spec syscall_spec_munlockall = { .name = "munlockall" };
struct syscall_spec syscall_spec_vhangup = { .name = "vhangup" };
struct syscall_spec syscall_spec_modify_ldt = { .name = "modify_ldt" };
struct syscall_spec syscall_spec_pivot_root = { .name = "pivot_root" };
struct syscall_spec syscall_spec__sysctl = { .name = "_sysctl" };
struct syscall_spec syscall_spec_prctl = { .name = "prctl" };
struct syscall_spec syscall_spec_arch_prctl = { .name = "arch_prctl" };
struct syscall_spec syscall_spec_adjtimex = { .name = "adjtimex" };
struct syscall_spec syscall_spec_setrlimit = { .name = "setrlimit" };
struct syscall_spec syscall_spec_chroot = { .name = "chroot" };
struct syscall_spec syscall_spec_sync = { .name = "sync" };
struct syscall_spec syscall_spec_acct = { .name = "acct" };
struct syscall_spec syscall_spec_settimeofday = { .name = "settimeofday" };
struct syscall_spec syscall_spec_mount = { .name = "mount" };
struct syscall_spec syscall_spec_umount2 = { .name = "umount2" };
struct syscall_spec syscall_spec_swapon = { .name = "swapon" };
struct syscall_spec syscall_spec_swapoff = { .name = "swapoff" };
struct syscall_spec syscall_spec_reboot = { .name = "reboot" };
struct syscall_spec syscall_spec_sethostname = { .name = "sethostname" };
struct syscall_spec syscall_spec_setdomainname = { .name = "setdomainname" };
struct syscall_spec syscall_spec_iopl = { .name = "iopl" };
struct syscall_spec syscall_spec_ioperm = { .name = "ioperm" };
struct syscall_spec syscall_spec_create_module = { .name = "create_module" };
struct syscall_spec syscall_spec_init_module = { .name = "init_module" };
struct syscall_spec syscall_spec_delete_module = { .name = "delete_module" };
struct syscall_spec syscall_spec_get_kernel_syms = { .name = "get_kernel_syms" };
struct syscall_spec syscall_spec_query_module = { .name = "query_module" };
struct syscall_spec syscall_spec_quotactl = { .name = "quotactl" };
struct syscall_spec syscall_spec_nfsservctl = { .name = "nfsservctl" };
struct syscall_spec syscall_spec_getpmsg = { .name = "getpmsg" };
struct syscall_spec syscall_spec_putpmsg = { .name = "putpmsg" };
struct syscall_spec syscall_spec_afs_syscall = { .name = "afs_syscall" };
struct syscall_spec syscall_spec_tuxcall = { .name = "tuxcall" };
struct syscall_spec syscall_spec_security = { .name = "security" };
struct syscall_spec syscall_spec_gettid = { .name = "gettid" };
struct syscall_spec syscall_spec_readahead = { .name = "readahead" };
struct syscall_spec syscall_spec_setxattr = { .name = "setxattr" };
struct syscall_spec syscall_spec_lsetxattr = { .name = "lsetxattr" };
struct syscall_spec syscall_spec_fsetxattr = { .name = "fsetxattr" };
struct syscall_spec syscall_spec_getxattr = { .name = "getxattr" };
struct syscall_spec syscall_spec_lgetxattr = { .name = "lgetxattr" };
struct syscall_spec syscall_spec_fgetxattr = { .name = "fgetxattr" };
struct syscall_spec syscall_spec_listxattr = { .name = "listxattr" };
struct syscall_spec syscall_spec_llistxattr = { .name = "llistxattr" };
struct syscall_spec syscall_spec_flistxattr = { .name = "flistxattr" };
struct syscall_spec syscall_spec_removexattr = { .name = "removexattr" };
struct syscall_spec syscall_spec_lremovexattr = { .name = "lremovexattr" };
struct syscall_spec syscall_spec_fremovexattr = { .name = "fremovexattr" };
struct syscall_spec syscall_spec_tkill = { .name = "tkill" };
struct syscall_spec syscall_spec_time = { .name = "time" };
struct syscall_spec syscall_spec_futex = { .name = "futex" };
struct syscall_spec syscall_spec_sched_setaffinity = { .name = "sched_setaffinity" };
struct syscall_spec syscall_spec_sched_getaffinity = { .name = "sched_getaffinity" };
struct syscall_spec syscall_spec_set_thread_area = { .name = "set_thread_area" };
struct syscall_spec syscall_spec_io_setup = { .name = "io_setup" };
struct syscall_spec syscall_spec_io_destroy = { .name = "io_destroy" };
struct syscall_spec syscall_spec_io_getevents = { .name = "io_getevents" };
struct syscall_spec syscall_spec_io_submit = { .name = "io_submit" };
struct syscall_spec syscall_spec_io_cancel = { .name = "io_cancel" };
struct syscall_spec syscall_spec_get_thread_area = { .name = "get_thread_area" };
struct syscall_spec syscall_spec_lookup_dcookie = { .name = "lookup_dcookie" };
struct syscall_spec syscall_spec_epoll_create = { .name = "epoll_create" };
struct syscall_spec syscall_spec_epoll_ctl_old = { .name = "epoll_ctl_old" };
struct syscall_spec syscall_spec_epoll_wait_old = { .name = "epoll_wait_old" };
struct syscall_spec syscall_spec_remap_file_pages = { .name = "remap_file_pages" };
struct syscall_spec syscall_spec_getdents64 = { .name = "getdents64" };
struct syscall_spec syscall_spec_set_tid_address = { .name = "set_tid_address" };
struct syscall_spec syscall_spec_restart_syscall = { .name = "restart_syscall" };
struct syscall_spec syscall_spec_semtimedop = { .name = "semtimedop" };
struct syscall_spec syscall_spec_fadvise64 = { .name = "fadvise64" };
struct syscall_spec syscall_spec_timer_create = { .name = "timer_create" };
struct syscall_spec syscall_spec_timer_settime = { .name = "timer_settime" };
struct syscall_spec syscall_spec_timer_gettime = { .name = "timer_gettime" };
struct syscall_spec syscall_spec_timer_getoverrun = { .name = "timer_getoverrun" };
struct syscall_spec syscall_spec_timer_delete = { .name = "timer_delete" };
struct syscall_spec syscall_spec_clock_settime = { .name = "clock_settime" };
struct syscall_spec syscall_spec_clock_gettime = { .name = "clock_gettime" };
struct syscall_spec syscall_spec_clock_getres = { .name = "clock_getres" };
struct syscall_spec syscall_spec_clock_nanosleep = { .name = "clock_nanosleep" };
struct syscall_spec syscall_spec_exit_group = { .name = "exit_group" };
struct syscall_spec syscall_spec_epoll_wait = { .name = "epoll_wait" };
struct syscall_spec syscall_spec_epoll_ctl = { .name = "epoll_ctl" };
struct syscall_spec syscall_spec_tgkill = { .name = "tgkill" };
struct syscall_spec syscall_spec_utimes = { .name = "utimes" };
struct syscall_spec syscall_spec_vserver = { .name = "vserver" };
struct syscall_spec syscall_spec_mbind = { .name = "mbind" };
struct syscall_spec syscall_spec_set_mempolicy = { .name = "set_mempolicy" };
struct syscall_spec syscall_spec_get_mempolicy = { .name = "get_mempolicy" };
struct syscall_spec syscall_spec_mq_open = { .name = "mq_open" };
struct syscall_spec syscall_spec_mq_unlink = { .name = "mq_unlink" };
struct syscall_spec syscall_spec_mq_timedsend = { .name = "mq_timedsend" };
struct syscall_spec syscall_spec_mq_timedreceive = { .name = "mq_timedreceive" };
struct syscall_spec syscall_spec_mq_notify = { .name = "mq_notify" };
struct syscall_spec syscall_spec_mq_getsetattr = { .name = "mq_getsetattr" };
struct syscall_spec syscall_spec_kexec_load = { .name = "kexec_load" };
struct syscall_spec syscall_spec_waitid = { .name = "waitid" };
struct syscall_spec syscall_spec_add_key = { .name = "add_key" };
struct syscall_spec syscall_spec_request_key = { .name = "request_key" };
struct syscall_spec syscall_spec_keyctl = { .name = "keyctl" };
struct syscall_spec syscall_spec_ioprio_set = { .name = "ioprio_set" };
struct syscall_spec syscall_spec_ioprio_get = { .name = "ioprio_get" };
struct syscall_spec syscall_spec_inotify_init = { .name = "inotify_init" };
struct syscall_spec syscall_spec_inotify_add_watch = { .name = "inotify_add_watch" };
struct syscall_spec syscall_spec_inotify_rm_watch = { .name = "inotify_rm_watch" };
struct syscall_spec syscall_spec_migrate_pages = { .name = "migrate_pages" };
struct syscall_spec syscall_spec_openat = { .name = "openat" };
struct syscall_spec syscall_spec_mkdirat = { .name = "mkdirat" };
struct syscall_spec syscall_spec_mknodat = { .name = "mknodat" };
struct syscall_spec syscall_spec_fchownat = { .name = "fchownat" };
struct syscall_spec syscall_spec_futimesat = { .name = "futimesat" };
struct syscall_spec syscall_spec_newfstatat = { .name = "newfstatat" };
struct syscall_spec syscall_spec_unlinkat = { .name = "unlinkat" };
struct syscall_spec syscall_spec_renameat = { .name = "renameat" };
struct syscall_spec syscall_spec_linkat = { .name = "linkat" };
struct syscall_spec syscall_spec_symlinkat = { .name = "symlinkat" };
struct syscall_spec syscall_spec_readlinkat = { .name = "readlinkat" };
struct syscall_spec syscall_spec_fchmodat = { .name = "fchmodat" };
struct syscall_spec syscall_spec_faccessat = { .name = "faccessat" };
struct syscall_spec syscall_spec_pselect6 = { .name = "pselect6" };
struct syscall_spec syscall_spec_ppoll = { .name = "ppoll" };
struct syscall_spec syscall_spec_unshare = { .name = "unshare" };
struct syscall_spec syscall_spec_set_robust_list = { .name = "set_robust_list" };
struct syscall_spec syscall_spec_get_robust_list = { .name = "get_robust_list" };
struct syscall_spec syscall_spec_splice = { .name = "splice" };
struct syscall_spec syscall_spec_tee = { .name = "tee" };
struct syscall_spec syscall_spec_sync_file_range = { .name = "sync_file_range" };
struct syscall_spec syscall_spec_vmsplice = { .name = "vmsplice" };
struct syscall_spec syscall_spec_move_pages = { .name = "move_pages" };
struct syscall_spec syscall_spec_utimensat = { .name = "utimensat" };
struct syscall_spec syscall_spec_epoll_pwait = { .name = "epoll_pwait" };
struct syscall_spec syscall_spec_signalfd = { .name = "signalfd" };
struct syscall_spec syscall_spec_timerfd_create = { .name = "timerfd_create" };
struct syscall_spec syscall_spec_eventfd = { .name = "eventfd" };
struct syscall_spec syscall_spec_fallocate = { .name = "fallocate" };
struct syscall_spec syscall_spec_timerfd_settime = { .name = "timerfd_settime" };
struct syscall_spec syscall_spec_timerfd_gettime = { .name = "timerfd_gettime" };
struct syscall_spec syscall_spec_accept4 = { .name = "accept4" };
struct syscall_spec syscall_spec_signalfd4 = { .name = "signalfd4" };
struct syscall_spec syscall_spec_eventfd2 = { .name = "eventfd2" };
struct syscall_spec syscall_spec_epoll_create1 = { .name = "epoll_create1" };
struct syscall_spec syscall_spec_dup3 = { .name = "dup3" };
struct syscall_spec syscall_spec_pipe2 = { .name = "pipe2" };
struct syscall_spec syscall_spec_inotify_init1 = { .name = "inotify_init1" };
struct syscall_spec syscall_spec_preadv = { .name = "preadv" };
struct syscall_spec syscall_spec_pwritev = { .name = "pwritev" };
struct syscall_spec syscall_spec_rt_tgsigqueueinfo = { .name = "rt_tgsigqueueinfo" };
struct syscall_spec syscall_spec_perf_event_open = { .name = "perf_event_open" };
struct syscall_spec syscall_spec_recvmmsg = { .name = "recvmmsg" };
struct syscall_spec syscall_spec_fanotify_init = { .name = "fanotify_init" };
struct syscall_spec syscall_spec_fanotify_mark = { .name = "fanotify_mark" };
struct syscall_spec syscall_spec_prlimit64 = { .name = "prlimit64" };
struct syscall_spec syscall_spec_name_to_handle_at = { .name = "name_to_handle_at" };
struct syscall_spec syscall_spec_open_by_handle_at = { .name = "open_by_handle_at" };
struct syscall_spec syscall_spec_clock_adjtime = { .name = "clock_adjtime" };
struct syscall_spec syscall_spec_syncfs = { .name = "syncfs" };
struct syscall_spec syscall_spec_sendmmsg = { .name = "sendmmsg" };
struct syscall_spec syscall_spec_setns = { .name = "setns" };
struct syscall_spec syscall_spec_getcpu = { .name = "getcpu" };
struct syscall_spec syscall_spec_process_vm_readv = { .name = "process_vm_readv" };
struct syscall_spec syscall_spec_process_vm_writev = { .name = "process_vm_writev" };
struct syscall_spec syscall_spec_kcmp = { .name = "kcmp" };
struct syscall_spec syscall_spec_finit_module = { .name = "finit_module" };
struct syscall_spec syscall_spec_sched_setattr = { .name = "sched_setattr" };
struct syscall_spec syscall_spec_sched_getattr = { .name = "sched_getattr" };
struct syscall_spec syscall_spec_renameat2 = { .name = "renameat2" };
struct syscall_spec syscall_spec_seccomp = { .name = "seccomp" };
struct syscall_spec syscall_spec_getrandom = { .name = "getrandom" };
struct syscall_spec syscall_spec_memfd_create = { .name = "memfd_create" };
struct syscall_spec syscall_spec_kexec_file_load = { .name = "kexec_file_load" };
struct syscall_spec syscall_spec_bpf = { .name = "bpf" };
struct syscall_spec syscall_spec_execveat = { .name = "execveat" };
struct syscall_spec syscall_spec_userfaultfd = { .name = "userfaultfd" };
struct syscall_spec syscall_spec_membarrier = { .name = "membarrier" };
struct syscall_spec syscall_spec_mlock2 = { .name = "mlock2" };
struct syscall_spec syscall_spec_copy_file_range = { .name = "copy_file_range" };
struct syscall_spec syscall_spec_preadv2 = { .name = "preadv2" };
struct syscall_spec syscall_spec_pwritev2 = { .name = "pwritev2" };
struct syscall_spec syscall_spec_pkey_mprotect = { .name = "pkey_mprotect" };
struct syscall_spec syscall_spec_pkey_alloc = { .name = "pkey_alloc" };
struct syscall_spec syscall_spec_pkey_free = { .name = "pkey_free" };
struct syscall_spec syscall_spec_waitpid = { .name = "waitpid" };

struct syscall_spec syscall_spec_sysctl = { .name = "sysctl" };
struct syscall_spec syscall_spec_sendfile64 = { .name = "sendfile64" };
struct syscall_spec syscall_spec_sigprocmask = { .name = "sigprocmask" };
struct syscall_spec syscall_spec_signal = { .name = "signal" };
struct syscall_spec syscall_spec_ssetmask = { .name = "ssetmask" };
struct syscall_spec syscall_spec_olduname = { .name = "olduname" };
struct syscall_spec syscall_spec_gethostname = { .name = "gethostname" };
struct syscall_spec syscall_spec_old_getrlimit = { .name = "old_getrlimit" };
struct syscall_spec syscall_spec_llseek = { .name = "llseek" };
struct syscall_spec syscall_spec_sigpending = { .name = "sigpending" };
struct syscall_spec syscall_spec_sigsuspend = { .name = "sigsuspend" };
struct syscall_spec syscall_spec_newuname = { .name = "newuname" };
struct syscall_spec syscall_spec_newstat = { .name = "newstat" };
struct syscall_spec syscall_spec_newlstat = { .name = "newlstat" };
struct syscall_spec syscall_spec_newfstat = { .name = "newfstat" };
struct syscall_spec syscall_spec_mmap_pgoff = { .name = "mmap_pgoff" };
struct syscall_spec syscall_spec_nice = { .name = "nice" };
struct syscall_spec syscall_spec_fadvise64_64 = { .name = "fadvist64_64" };
struct syscall_spec syscall_spec_old_readdir = { .name = "old_readdir" };
struct syscall_spec syscall_spec_umount = { .name = "umount" };
struct syscall_spec syscall_spec_oldumount = { .name = "oldumount" };
struct syscall_spec syscall_spec_stime = { .name = "stime" };
struct syscall_spec syscall_spec_send = { .name = "send" };
struct syscall_spec syscall_spec_recv = { .name = "recv" };
struct syscall_spec syscall_spec_socketcall = { .name = "socketcall" };
struct syscall_spec syscall_spec_lchown16 = { .name = "lchown16" };
struct syscall_spec syscall_spec_fchown16 = { .name = "fchown16" };
struct syscall_spec syscall_spec_setregid16 = { .name = "setregid16" };
struct syscall_spec syscall_spec_setgid16 = { .name = "setgid16" };
struct syscall_spec syscall_spec_setreuid16 = { .name = "setreuid16" };
struct syscall_spec syscall_spec_setuid16 = { .name = "setuid16" };
struct syscall_spec syscall_spec_setresuid16 = { .name = "setresuid16" };
struct syscall_spec syscall_spec_setsuid16 = { .name = "setsuid16" };
struct syscall_spec syscall_spec_chown16 = { .name = "chown16" };
struct syscall_spec syscall_spec_getresuid16 = { .name = "getresuid16" };
struct syscall_spec syscall_spec_setresgid16 = { .name = "setresgid16" };
struct syscall_spec syscall_spec_getresgid16 = { .name = "getresgid16" };
struct syscall_spec syscall_spec_setfsuid16 = { .name = "setfsuid16" };
struct syscall_spec syscall_spec_setfsgid16 = { .name = "setfsgid16" };
struct syscall_spec syscall_spec_getgroups16 = { .name = "getgroups16" };
struct syscall_spec syscall_spec_setgroups16 = { .name = "sethroups16" };
struct syscall_spec syscall_spec_sync_file_range2 = { .name = "sync_file_range2" };
struct syscall_spec syscall_spec_statfs64 = { .name = "statfs64" };
struct syscall_spec syscall_spec_fstatfs64 = { .name = "fstatfs64" };
struct syscall_spec syscall_spec_bdflush = { .name = "bdflush" };

#undef $
