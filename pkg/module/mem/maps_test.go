package mem

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

const bytesPerWord = (32 << (^uint(0) >> 63)) / 8

func align(bytes int) int {
	return ((bytes + bytesPerWord - 1) / bytesPerWord) * bytesPerWord
}

func TestSizeofFdKey(t *testing.T) {
	assert.Equal(t, 8, int(unsafe.Sizeof(FdsKey{})))
}

func TestSizeofFdValue(t *testing.T) {
	assert.Equal(t, 1, int(unsafe.Sizeof(FdsValue{})))
}

func TestSizeofEvent(t *testing.T) {
	assert.Equal(t, 16, int(unsafe.Sizeof(Event{})))
}

func TestAlignEmpty(t *testing.T) {
	assert.Equal(t, 0, align(0))
}

func TestAlignOneByte(t *testing.T) {
	assert.Equal(t, bytesPerWord, align(1))
}

func TestAlignOneByteWord(t *testing.T) {
	assert.Equal(t, bytesPerWord, align(bytesPerWord))
}

func TestUnmarshalEventSysEnterMmap(t *testing.T) {
	b := make([]byte, 0, 16)
	b = binary.LittleEndian.AppendUint64(b, 0x0000000000000000)
	b = binary.LittleEndian.AppendUint64(b, 0x00044b8f00000003)

	r := bytes.NewReader(b)
	e := Event{}
	err := binary.Read(r, binary.NativeEndian, &e)
	assert.NoError(t, err)
	assert.Equal(t, uint64(EVENT_TYPE_SYS_ENTER_MMAP), e.Type)
	assert.Equal(t, uint32(0x00044b8f), e.GetSysEnterMmapPid())
	assert.Equal(t, uint32(3), e.GetSysEnterMmapFd())
}

func TestUnmarshalEventSysEnterMunmap(t *testing.T) {
	b := make([]byte, 0, 16)
	b = binary.LittleEndian.AppendUint64(b, 0x0000000000000001)
	b = binary.LittleEndian.AppendUint64(b, 0x0000000000000000)

	r := bytes.NewReader(b)
	e := Event{}
	err := binary.Read(r, binary.NativeEndian, &e)
	assert.NoError(t, err)
	assert.Equal(t, uint64(EVENT_TYPE_SYS_ENTER_MUNMAP), e.Type)
}

func TestUnmarshalEventSysExitMmap(t *testing.T) {
	b := make([]byte, 0, 16)
	b = binary.LittleEndian.AppendUint64(b, 0x0000000000000002)
	b = binary.LittleEndian.AppendUint64(b, 0xffffffffb458c000)

	r := bytes.NewReader(b)
	e := Event{}
	err := binary.Read(r, binary.NativeEndian, &e)
	assert.NoError(t, err)
	assert.Equal(t, uint64(EVENT_TYPE_SYS_EXIT_MMAP), e.Type)
	x := 0xb458c000
	assert.Equal(t, int32(x), e.GetSysExitMmapRet())
}

func TestUnmarshalEventSysExitMunmap(t *testing.T) {
	b := make([]byte, 0, 16)
	b = binary.LittleEndian.AppendUint64(b, 0x0000000000000003)
	b = binary.LittleEndian.AppendUint64(b, 0x0000000000000000)

	r := bytes.NewReader(b)
	e := Event{}
	err := binary.Read(r, binary.NativeEndian, &e)
	assert.NoError(t, err)
	assert.Equal(t, uint64(EVENT_TYPE_SYS_EXIT_MUNMAP), e.Type)
	assert.Equal(t, int32(0), e.GetSysExitMunmapRet())
}
