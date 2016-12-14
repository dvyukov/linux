#ifndef ABISPEC_H_
#define ABISPEC_H_

struct syscall_spec;

void abispec_init(void);
void abispec_check_pre(struct syscall_spec *s, ...);
void abispec_check_post(struct syscall_spec *s, long retval, ...);

#endif
