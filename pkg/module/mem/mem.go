package mem

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/christian-2/ai-ray/pkg/logger"
	"github.com/christian-2/ai-ray/pkg/module"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

var (
	log = logger.GetLogger()
)

type Mem struct {
	module.AbstractModule

	// eBPF map for communicating from user space to kernel space
	fdsMap *ebpf.Map

	// eBPF ring buffer for communicating from kernel space to user space
	rbMap *ebpf.Map

	// ring buffer reader that drives state machine
	rbReader *ringbuf.Reader
}

func NewModule(objFile string) (*Mem, error) {
	s := module.ModuleSpec{ObjFile: objFile}
	a := module.AbstractModule{Spec: s}
	return &Mem{AbstractModule: a}, nil
}

func (m *Mem) LoadAndAttach() error {
	if err := m.AbstractModule.LoadAndAttach(); err != nil {
		return err
	}

	// identify specific eBPS maps and do some sanity checks on all:w

	for name, ms := range m.AbstractModule.CollectionSpec.Maps {
		mm := m.AbstractModule.Collection.Maps[name]

		var type_ ebpf.MapType
		var keySize, valueSize uint32
		switch ms.Name {
		case "fds":
			m.fdsMap = mm

			type_ = ebpf.Hash
			keySize = uint32(unsafe.Sizeof(FdsKey{}))
			valueSize = uint32(unsafe.Sizeof(FdsValue{}))
		case "rb":
			m.rbMap = mm

			type_ = ebpf.RingBuf
			keySize = 0
			valueSize = 0 // variable length
		default:
			return fmt.Errorf("unexpected map: %v", ms.Name)
		}

		log.WithFields(logrus.Fields{
			"name":       ms.Name,
			"type":       ms.Type,
			"keySize":    ms.KeySize,
			"valueSize":  ms.ValueSize,
			"maxEntries": ms.MaxEntries,
			"pinning":    ms.Pinning}).
			Info("loaded map")

		if (ms.Type != type_) ||
			(ms.KeySize != keySize) || (ms.ValueSize != valueSize) {
			return fmt.Errorf("mismatch between Go and C parts")
		}
		if ms.Pinning != ebpf.PinByName {
			return fmt.Errorf("map not automatically pinned: %v",
				ms.Name)
		}
	}
	return nil
}

func (m *Mem) Start() error {
	r, err := ringbuf.NewReader(m.rbMap)
	if err != nil {
		return err
	}
	m.rbReader = r

	rec := ringbuf.Record{}
	e := Event{}

	// run state machine until rbr.Close() was called
	for {
		err := m.rbReader.ReadInto(&rec)
		if errors.Is(err, os.ErrClosed) {
			// finish loop when rbr.Close() was called
			return nil
		} else if err != nil {
			return errors.New("cannot read from ring buffer")
		}

		log.WithFields(logrus.Fields{
			"size":      len(rec.RawSample),
			"remaining": rec.Remaining,
			"hex":       hex.EncodeToString(rec.RawSample)}).
			Info("read from ring buffer")

		r := bytes.NewReader(rec.RawSample)
		err = binary.Read(r, binary.NativeEndian, &e)
		if err != nil {
			log.WithError(err).Fatal("cannot deserialize event")
		}

		switch e.Type {
		case EVENT_TYPE_SYS_ENTER_MMAP:
			pid := e.GetSysEnterMmapPid()
			fd := e.GetSysEnterMmapFd()
			sysEnterMmap(pid, fd)
		case EVENT_TYPE_SYS_ENTER_MUNMAP:
			sysEnterMunmap()
		case EVENT_TYPE_SYS_EXIT_MMAP:
			ret := e.GetSysExitMmapRet()
			sysExitMmap(ret)
		case EVENT_TYPE_SYS_EXIT_MUNMAP:
			ret := e.GetSysExitMunmapRet()
			sysExitMunmap(ret)
		default:
			log.WithFields(logrus.Fields{
				"type": e.Type}).
				Error("unknown event type")
		}
	}
}

func (m *Mem) Stop() error {
	// cause Start() to finish its loop
	if err := m.rbReader.Close(); err != nil {
		return err
	} else {
		m.rbReader = nil
		return nil
	}
}

func sysEnterMmap(pid uint32, fd uint32) {
	log.WithFields(logrus.Fields{"pid": pid, "fd": fd}).Info("sysEnterMmap")
	// TODO
}

func sysEnterMunmap() {
	log.Info("sysEnterMunmap")
	// TODO
}

func sysExitMmap(ret int32) {
	log.WithFields(logrus.Fields{"ret": ret}).Info("sysExitMmap")
	// TODO
}

func sysExitMunmap(ret int32) {
	log.WithFields(logrus.Fields{"ret": ret}).Info("sysExitMunmap")
	// TODO
}
