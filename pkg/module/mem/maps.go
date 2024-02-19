//go:build ignore

package mem

// #include <linux/types.h>
// #include "./bpf/mem/maps.h"
import "C"

type FdsKey C.struct_fds_key
type FdsValue C.struct_fds_value

const EVENT_TYPE_SYS_ENTER_MMAP = C.EVENT_TYPE_SYS_ENTER_MMAP
const EVENT_TYPE_SYS_ENTER_MUNMAP = C.EVENT_TYPE_SYS_ENTER_MUNMAP
const EVENT_TYPE_SYS_EXIT_MMAP = C.EVENT_TYPE_SYS_EXIT_MMAP
const EVENT_TYPE_SYS_EXIT_MUNMAP = C.EVENT_TYPE_SYS_EXIT_MUNMAP

// events sent from kernel space to user space via map rb
type Event C.struct_event

func (e *Event) GetSysEnterMmapPid() uint32 {
	return uint32(e.Payload >> 32)
}

func (e *Event) GetSysEnterMmapFd() uint32 {
	return uint32(e.Payload & 0xFFFFFFFF)
}

func (e *Event) GetSysExitMmapRet() int32 {
	return int32(e.Payload)
}

func (e *Event) GetSysExitMunmapRet() int32 {
	return int32(e.Payload)
}
