#ifndef ABI_SPEC_H_
#define ABI_SPEC_H_

#include <linux/types.h>

#define ABI_MAX_ARGS	6
#define ABI_MAX_FIELDS	10
#define ABI_MAX_ERRNO	64
#define ABI_MAX_BITMASK	32

#define ABI_IN		(1 << 0)
#define ABI_OUT		(1 << 1)
#define ABI_DTOR	(1 << 2)
#define ABI_ARG		(1 << 3)

#define	KIND_SCALAR	1
#define KIND_PTR	2
#define KIND_ARRAY	3
#define KIND_STRUCT	4
#define KIND_UNION	5
#define KIND_RESOURCE	6

#define RES_FD		1
#define RES_PATHNAME	2

#define CONSTRAINT_BITMASK	1

struct type;

struct argument {
	const char	*name;
	struct type	*type;
	int		flags;
};

/*
TODO:

bitmask
oneof
range
const
length(field)

bitsize

optional (only pointers)
resource values

strings

buffer/array ranges

vma (pointer to array of pages)
*/

struct type {
	int		kind;
	union {
		// KIND_SCALAR
		struct {
			int		size;
			int		constraint;
			union {
				struct {
					long long	val;
					const char	*str;
				} bitmask[ABI_MAX_BITMASK];
			};
			
			//int		align;
			// bit offset, bit size for bitfields
		} scalar;

		// KIND_PTR
		struct {
			struct type	*type;
		} ptr;

		// KIND_ARRAY
		struct {
			struct type	*type;
		} array;

		// KIND_STRUCT
		struct {
			struct argument	fields[ABI_MAX_FIELDS];
			bool		packed;
		} str;

		// KIND_UNION
		struct {
			struct argument	fields[ABI_MAX_FIELDS];
			bool		varlen;
		} uni;

		// KIND_RESOURCE
		struct {
			int		res;	// RES_*
			struct type	*type;
		} res;
	};
};

/* A generic syscall */
struct syscall_spec {
	const char 	*name;
	int 		errno[ABI_MAX_ERRNO];
	struct type	*ret;
	struct argument	args[ABI_MAX_ARGS];
};

#endif
