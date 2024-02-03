
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "maps.h"

char _license[] SEC("license") = "GPL";

#define FDS_MAX_ENTRIES 1024
#define RB_MAX_ENTRIES 4096

// map for communication from user space to kernel space
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct fds_key);
	__type(value, struct fds_value);
	__uint(max_entries, FDS_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} VM_FDS SEC(".maps");

// map for communication from kernel space to user space
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RB_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} VM_RB SEC(".maps");

struct common_header {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_cound;
	__s32 common_pid;
};

SEC("kprobe/handle_mm_fault")
int handle_mm_fault(
	struct pt_regs *reg
) {
#ifdef DEBUG
	char fmt[] = "handle_mm_fault\n";
	bpf_trace_printk(fmt, sizeof(fmt));
#endif

	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_write_folio")
int mm_vmscan_write_folio(
	void *ctx
) {
#ifdef DEBUG
	char fmt[] = "mm_vmscan_write_folio\n";
	bpf_trace_printk(fmt, sizeof(fmt));
#endif

	return 0;
}

// see /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct sys_enter_mmap_ctx {
	struct common_header header;
	__s32 syscall_nr;
	__u64 addr;
	__u64 length;
	__u64 prot;
	__u64 flags;
	__u64 fd;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int sys_enter_mmap(
	struct sys_enter_mmap_ctx *ctx
) {
#ifdef DEBUG
	char fmt[] = "sys_enter_mmap";
	bpf_trace_printk(fmt, sizeof(fmt));
#endif
	struct event *e;
	e = bpf_ringbuf_reserve(&VM_RB, sizeof(*e), 0);
	if (e == NULL) {
		char fmt[] = "sys_enter_mmap: cannot reserve %d bytes";
		bpf_trace_printk(fmt, sizeof(fmt), sizeof(*e));
 		return 0;
	}

	e->type = EVENT_TYPE_SYS_ENTER_MMAP;
	e->sys_enter_mmap_pid = bpf_get_current_pid_tgid() >> 32;
	e->sys_enter_mmap_fd  = (__s32)ctx->fd;
	
	bpf_ringbuf_submit(e, 0); // w/ adaptive notification
	return 0;
}

// see /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/format
struct sys_enter_munmap_ctx {
	struct common_header header;
	__s32 syscall_nr;
	__u64 addr;
	__u64 len;
};

SEC("tracepoint/syscalls/sys_enter_munmap")
int sys_enter_munmap(
	struct sys_enter_munmap_ctx *ctx
) {
#ifdef DEBUG
	char fmt[] = "sys_enter_munmap";
	bpf_trace_printk(fmt, sizeof(fmt));
#endif
	struct event *e;
	e = bpf_ringbuf_reserve(&VM_RB, sizeof(*e), 0);
	if (e == NULL) {
		char fmt[] = "sys_enter_munmap: cannot reserve %d bytes";
		bpf_trace_printk(fmt, sizeof(fmt), sizeof(*e));
 		return 0;
	}

	e->type = EVENT_TYPE_SYS_ENTER_MUNMAP;
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// see /sys/kernel/debug/tracing/events/syscalls/sys_exit_mmap/format
struct sys_exit_mmap_ctx {
	struct common_header header;
	__s32 syscall_nr;
	__s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_mmap")
int sys_exit_mmap(
	struct sys_exit_mmap_ctx *ctx
) {
#ifdef DEBUG
	char fmt[] = "sys_exit_mmap";
	bpf_trace_printk(fmt, sizeof(fmt));
#endif
	struct event *e;
	e = bpf_ringbuf_reserve(&VM_RB, sizeof(*e), 0);
	if (e == NULL) {
		char fmt[] = "sys_exit_mmap: cannot reserve %d bytes";
		bpf_trace_printk(fmt, sizeof(fmt), sizeof(*e));
 		return 0;
	}

	e->type = EVENT_TYPE_SYS_EXIT_MMAP;
	e->sys_exit_mmap_ret = (__s32)ctx->ret;
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// see /sys/kernel/debug/tracing/events/syscalls/sys_exit_munmap/format
struct sys_exit_munmap_ctx {
	struct common_header header;
	__s32 syscall_nr;
	__u64 ret;
};

SEC("tracepoint/syscalls/sys_exit_munmap")
int sys_exit_munmap(
	struct sys_exit_munmap_ctx *ctx
) {
#ifdef DEBUG
	char fmt[] = "sys_exit_munmap";
	bpf_trace_printk(fmt, sizeof(fmt));
#endif
	struct event *e;
	e = bpf_ringbuf_reserve(&VM_RB, sizeof(*e), 0);
	if (e == NULL) {
		char fmt[] = "sys_exit_munmap: cannot reserve %d bytes";
		bpf_trace_printk(fmt, sizeof(fmt), sizeof(*e));
 		return 0;
	}

	e->type = EVENT_TYPE_SYS_EXIT_MUNMAP;
	e->sys_exit_munmap_ret = (__s32)ctx->ret;
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}
