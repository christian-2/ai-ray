package bpf

// ATTENTION: file must be kept aligned with bpf/maps.h

const (
	VM_FDS = "fds"
	VM_RB  = "rb"
)

const (
	EVENT_TYPE_SYS_ENTER_MMAP = iota
	EVENT_TYPE_SYS_ENTER_MUNMAP
	EVENT_TYPE_SYS_EXIT_MMAP
	EVENT_TYPE_SYS_EXIT_MUNMAP
)

// data sent from user space to kernel space via map fds

type FdsKey struct {
	Pid uint32
	Fd  int32
}

type FdsValue struct {
	_ uint8 // not used
}

type Payload [2]uint32

// events sent from kernel space to user space via map rb
type Event struct {
	Type    uint64
	Payload Payload
}
