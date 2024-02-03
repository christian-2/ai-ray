package sm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"

	"github.com/christian-2/ai-ray/pkg/bpf"
	"github.com/christian-2/ai-ray/pkg/logger"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

var (
	log = logger.GetLogger()
)

type stateMachine struct {
	rbr *ringbuf.Reader
}

func NewStateMachine(ringbufMap *ebpf.Map) (*stateMachine, error) {
	rbr, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, err
	}

	return &stateMachine{rbr: rbr}, nil
}

func (sm *stateMachine) Run() error {
	rec := ringbuf.Record{}
	event := bpf.Event{}

	// run state machine until rbr.Close() was called
	for {
		err := sm.rbr.ReadInto(&rec)
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
		err = binary.Read(r, binary.NativeEndian, &event)
		if err != nil {
			log.WithError(err).Fatal("cannot deserialize event")
		}

		switch event.Type {
		case bpf.EVENT_TYPE_SYS_ENTER_MMAP:
			pid := event.Payload[0]
			fd := int32(event.Payload[0])
			sysEnterMmap(pid, fd)
		case bpf.EVENT_TYPE_SYS_ENTER_MUNMAP:
			sysEnterMunmap()
		case bpf.EVENT_TYPE_SYS_EXIT_MMAP:
			ret := int32(event.Payload[0])
			sysExitMmap(ret)
		case bpf.EVENT_TYPE_SYS_EXIT_MUNMAP:
			ret := int32(event.Payload[0])
			sysExitMunmap(ret)
		default:
			log.WithFields(logrus.Fields{
				"type": event.Type}).
				Error("unknown event type")
		}
	}
}

func (sm *stateMachine) Stop() error {
	// cause Start() to finish its loop
	return sm.rbr.Close()
}

func sysEnterMmap(pid uint32, fd int32) {
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
