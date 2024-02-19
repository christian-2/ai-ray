
enum {
	EVENT_TYPE_SYS_ENTER_MMAP,
	EVENT_TYPE_SYS_ENTER_MUNMAP,
	EVENT_TYPE_SYS_EXIT_MMAP,
	EVENT_TYPE_SYS_EXIT_MUNMAP
};

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
	__u64 payload;
};

void set_event_sys_enter_mmap(struct event *e, __u32 pid, __u32 fd);
void set_event_sys_enter_munmap(struct event *e);
void set_event_sys_exit_mmap(struct event *e, __s32 ret);
void set_event_sys_exit_munmap(struct event *e, __s32 ret);
