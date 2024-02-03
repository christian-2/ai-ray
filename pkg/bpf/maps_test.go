package bpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

const bytesPerWord = (32 << (^uint(0) >> 63)) / 8

func align(bytes int) int {
	return ((bytes + bytesPerWord - 1) / bytesPerWord) * bytesPerWord
}

func TestSizeofFdKey(t *testing.T) {
	require.Equal(t, 8, int(unsafe.Sizeof(FdsKey{})))
}

func TestSizeofFdValue(t *testing.T) {
	require.Equal(t, 1, int(unsafe.Sizeof(FdsValue{})))
}

func TestSizeofEvent(t *testing.T) {
	require.Equal(t, 16, int(unsafe.Sizeof(Event{})))
}

func TestAlignEmpty(t *testing.T) {
	require.Equal(t, 0, align(0))
}

func TestAlignOneByte(t *testing.T) {
	require.Equal(t, bytesPerWord, align(1))
}

func TestAlignOneByteWord(t *testing.T) {
	require.Equal(t, bytesPerWord, align(bytesPerWord))
}
