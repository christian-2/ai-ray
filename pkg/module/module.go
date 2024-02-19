package module

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/christian-2/ai-ray/pkg/common"
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

type Module interface {
	LoadAndAttach() error

	Start() error
	Stop() error

	Unload() error
}

type ModuleSpec struct {

	// optional ELF file where BPF program resudes
	ObjFile string

	// optional HTTP handler
	Handler http.Handler
}

type AbstractModule struct {
	Module
	Spec ModuleSpec

	CollectionSpec *ebpf.CollectionSpec
	Collection     *ebpf.Collection
}

func (a *AbstractModule) LoadAndAttach() error {
	if a.Spec.ObjFile == "" {
		return nil
	}

	// parse ELF file

	log.WithFields(logrus.Fields{
		"objFile": a.Spec.ObjFile}).
		Info("parse ELF file")
	cs, err := ebpf.LoadCollectionSpec(a.Spec.ObjFile)
	if err != nil {
		return fmt.Errorf("cannot parse ELF file: %w", err)
	}
	a.CollectionSpec = cs

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

	ex, err := os.Executable()
	if err != nil {
		return err
	}
	b1 := filepath.Base(ex)
	b2 := filepath.Base(a.Spec.ObjFile)
	b2 = strings.TrimSuffix(b2, filepath.Ext(b2))

	pp := path.Join(core.GetBpffsMountPoint(), b1, b2)
	err = os.MkdirAll(pp, 0700)
	if err != nil {
		return err
	}
	mo := ebpf.MapOptions{PinPath: pp}
	var po ebpf.ProgramOptions
	if common.Debug {
		po = ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch |
				ebpf.LogLevelInstruction |
				ebpf.LogLevelStats}
	}
	opts := ebpf.CollectionOptions{Maps: mo, Programs: po}

	log.WithFields(logrus.Fields{
		"programs": len(cs.Programs),
		"maps":     len(cs.Maps),
		"pinPath":  pp}).
		Info("load programs and maps into kernel")
	c, err := ebpf.NewCollectionWithOptions(cs, opts)

	for name, p := range c.Programs {
		l := "\n--- " + name + "\n" + p.VerifierLog + "---"
		log.WithFields(logrus.Fields{"log": l}).Debug("verifier")
	}

	if err != nil {
		return fmt.Errorf("cannot load programs and maps"+
			" into kernel: %w", err)
	}
	a.Collection = c

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

func (a *AbstractModule) Unload() error {
	log.WithFields(logrus.Fields{
		"programs": len(a.CollectionSpec.Programs),
		"maps":     len(a.CollectionSpec.Maps)}).
		Info("freeing programs and maps")
	a.Collection.Close()
	a.Collection = nil
	return nil
}
