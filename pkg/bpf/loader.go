package bpf

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"unsafe"

	"github.com/christian-2/ai-ray/pkg/core"
	"github.com/christian-2/ai-ray/pkg/logger"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	log = logger.GetLogger()
)

type Loader struct {
	FdsMap *ebpf.Map
	RbMap  *ebpf.Map

	file           string
	debug          bool
	collectionSpec *ebpf.CollectionSpec
	collection     *ebpf.Collection
}

func NewLoader(file string, debug bool) *Loader {
	return &Loader{file: file, debug: debug}
}

func (l *Loader) LoadAndAttach() error {

	// parse ELF file

	log.WithFields(logrus.Fields{
		"file": l.file}).
		Info("parse ELF file")
	cs, err := ebpf.LoadCollectionSpec(l.file)
	if err != nil {
		return fmt.Errorf("cannot parse ELF file: %w", err)
	}
	l.collectionSpec = cs

	// apply workaround for cilium/ebpf issue #1327

	for _, ps := range cs.Programs {
		if ps.Type == ebpf.Syscall {
			log.WithFields(logrus.Fields{
				"issue": "#1327"}).
				Info("apply workaround")
			ps.Flags |= unix.BPF_F_SLEEPABLE
		}
	}

	// load eBPF programs and maps into kernel

	bp := path.Join(core.GetBpffsMountPoint(), "ai-ray", "vm")
	err = os.MkdirAll(bp, 0700)
	if err != nil {
		return fmt.Errorf("cannot make directory: %v", err)
	}
	mo := ebpf.MapOptions{PinPath: bp}
	var po ebpf.ProgramOptions
	if l.debug {
		po = ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch |
				ebpf.LogLevelInstruction |
				ebpf.LogLevelStats}
	}
	opts := ebpf.CollectionOptions{Maps: mo, Programs: po}

	log.WithFields(logrus.Fields{
		"programs": len(cs.Programs),
		"maps":     len(cs.Maps),
		"pinPath":  bp}).
		Info("load programs and maps into kernel")
	c, err := ebpf.NewCollectionWithOptions(cs, opts)

	if l.debug {
		for name, p := range c.Programs {
			l := "\n--- " + name + "\n" + p.VerifierLog + "---"
			log.WithFields(logrus.Fields{"log": l}).Info("verifier")
		}
	}
	if err != nil {
		return fmt.Errorf("cannot load programs and maps"+
			" into kernel: %w", err)
	}
	l.collection = c

	// do some sanity checks on maps

	for name, ms := range cs.Maps {
		m := c.Maps[name]

		var type_ ebpf.MapType
		var keySize, valueSize uint32
		switch ms.Name {
		case VM_FDS:
			l.FdsMap = m

			type_ = ebpf.Hash
			keySize = uint32(unsafe.Sizeof(FdsKey{}))
			valueSize = uint32(unsafe.Sizeof(FdsValue{}))
		case VM_RB:
			l.RbMap = m

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

	// attach eBPF programs

	for name, ps := range cs.Programs {
		p := c.Programs[name]

		switch ps.Type {
		case ebpf.Kprobe:
			symbol := ps.AttachTo
			var opts *link.KprobeOptions
			log.WithFields(logrus.Fields{
				"type":    ps.Type,
				"program": ps.Name,
				"symbol":  symbol}).
				Info("attach program")
			_, err := link.Kprobe(symbol, p, opts)
			if err != nil {
				return fmt.Errorf("cannot attach program"+
					" %v: %v", symbol, err)
			}
		case ebpf.TracePoint:
			s := strings.Split(ps.AttachTo, "/")
			group := s[0]
			name := s[1]
			var opts *link.TracepointOptions
			log.WithFields(logrus.Fields{
				"type":    ps.Type,
				"program": ps.Name,
				"group":   group,
				"name":    name}).
				Info("attach program")
			_, err := link.Tracepoint(group, name, p, opts)
			if err != nil {
				return fmt.Errorf("cannot attach program"+
					" %v/%v: %v", group, name, err)
			}
		default:
			return errors.New("unexpected program type")
		}
	}

	return err
}

// Unload unloads eBPF programs and maps from kernel.
func (l *Loader) Close() error {
	log.WithFields(logrus.Fields{
		"programs": len(l.collectionSpec.Programs),
		"maps":     len(l.collectionSpec.Maps)}).
		Info("freeing programs and maps")
	l.collection.Close()
	l.collection = nil

	return nil
}
