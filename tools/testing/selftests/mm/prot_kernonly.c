// SPDX-License-Identifier: GPL-2.0
#include <err.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define PROT_KERNONLY 0x40

int skip_segv;
jmp_buf segv_env;
char* mem;

bool trywrite(void* p)
{
	int ok = 1;
	__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST);
	if (_setjmp(segv_env) == 0)
		*(volatile char*)p = 1;
	else
		ok = 0;
	__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST);
	return ok;
}

bool trysyscall(void* p)
{
	int res = sigaltstack(NULL, (stack_t*)p);
	if (res && errno != EFAULT)
		errx(1, "unexpected syscall errno");
	return res == 0;
}

void tryaccess(const char* what)
{
	printf("%s: syscall=%d\n", what, trysyscall(mem));
	printf("%s: write=%d\n", what, trywrite(mem));
}

void sighandler(int signo, siginfo_t* siginfo, void* uctx)
{
	printf("signal(%d): si_code=%d si_addr=%p\n",
	       signo, siginfo->si_code, siginfo->si_addr);
	if (__atomic_load_n(&skip_segv, __ATOMIC_RELAXED))
		longjmp(segv_env, 1);
	_exit(1);
}

int main(int argc, char** argv)
{
	struct sigaction act = {};
	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO | SA_NODEFER;
	if (sigaction(SIGBUS, &act, NULL))
		errx(1, "sigaction");
	if (sigaction(SIGSEGV, &act, NULL))
		errx(1, "sigaction");

	mem = (char*)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANON, -1, 0);
	if (mem == MAP_FAILED)
		errx(1, "mmap");
	tryaccess("RW");

	if (mprotect(mem, 4096, PROT_NONE))
		errx(1, "mprotect");
	tryaccess("NONE");

	if (mprotect(mem, 4096, PROT_NONE | PROT_KERNONLY))
		errx(1, "mprotect");
	tryaccess("NONE|KERNONLY");

	if (mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_KERNONLY))
		errx(1, "mprotect");
	tryaccess("RW|KERNONLY");

	if (mprotect(mem, 4096, PROT_READ | PROT_WRITE))
		errx(1, "mprotect");
	tryaccess("RW");

	mem = (char*)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_KERNONLY,
		MAP_PRIVATE | MAP_ANON, -1, 0);
	if (mem == MAP_FAILED)
		errx(1, "mmap");
	tryaccess("RW|KERNONLY(mmap)");

	if (mprotect(mem, 4096, PROT_READ | PROT_WRITE))
		errx(1, "mprotect");
	tryaccess("RW");
}
