
// ATTENTION: file must be kept aligned with pkg/bpf/maps.go

// names of maps
#define VM_FDS fds
#define VM_RB  rb

#define EVENT_TYPE_SYS_ENTER_MMAP   0
#define EVENT_TYPE_SYS_ENTER_MUNMAP 1
#define EVENT_TYPE_SYS_EXIT_MMAP    2
#define EVENT_TYPE_SYS_EXIT_MUNMAP  3

struct fds_key {
	__u32 pid;
	__u32 fd;
};

struct fds_value {
	__u8 _; // not used
};

// events sent from kernel space to user space via map rb
struct event {
	__u64 type;
	union {
		struct { // OPCODE_SYS_ENTER_MMAP
			__u32 sys_enter_mmap_pid:32;
			__s32 sys_enter_mmap_fd:32;
		};
		struct { // OPCODE_SYS_ENTER_MUNMAP
		};
		struct { // OPCODE_SYS_EXIT_MMAP
			__s32 sys_exit_mmap_ret;
		};
		struct { // OPCODE_SYS_EXIT_MUNMAP
			__s32 sys_exit_munmap_ret;
		};
        };
};
