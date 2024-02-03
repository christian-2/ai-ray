package core

import (
	"syscall"
)

func GetBpffsMountPoint() string {
	return "/sys/fs/bpf/"
}

func GetKernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	} else {
		return int8ToString(u.Release[:]) // e.g. "6.1.0-16-amd64"
	}
}

func int8ToString(ii []int8) string {
	bb := make([]byte, 0, len(ii))
	for _, i := range ii {
		if i == 0x00 {
			break
		}
		bb = append(bb, byte(i))
	}
	return string(bb)
}
