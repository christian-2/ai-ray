package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/christian-2/ai-ray/pkg/bpf"
	"github.com/christian-2/ai-ray/pkg/core"
	"github.com/christian-2/ai-ray/pkg/http"
	"github.com/christian-2/ai-ray/pkg/logger"
	"github.com/christian-2/ai-ray/pkg/sm"
	"github.com/sirupsen/logrus"
)

var (
	KERNEL_RELEASES string // injected as build-time variable

	log = logger.GetLogger()
)

func main() {

	// parse command-line options

	addr := flag.String("addr", ":8080", "HTTP server")
	debug := flag.Bool("debug", false, "display debugging information")
	flag.Parse()

	// check kernel version

	krActual := core.GetKernelRelease()
	log.WithFields(logrus.Fields{"release": krActual}).Info("kernel")
	ok := false
	for _, krExpected := range strings.Split(KERNEL_RELEASES, ",") {
		if krActual == krExpected {
			ok = true
			break
		}
	}
	if !ok {
		log.WithFields(logrus.Fields{
			"actual":   krActual,
			"expected": KERNEL_RELEASES}).
			Warning("unsupported kernel")
	}

	// load eBPF programs and maps

	ex, err := os.Executable()
	if err != nil {
		log.WithError(err).Fatal("Executable")
	}
	obj := filepath.Join(filepath.Dir(ex), "../bpf/vm.o")

	l := bpf.NewLoader(obj, *debug)
	err = l.LoadAndAttach()
	if err != nil {
		log.WithError(err).Fatal("Load")
	}
	defer func() {
		if err := l.Close(); err != nil {
			log.WithError(err).Fatal("Close")
		}
	}()

	// manage goroutines

	hs := http.NewHttpServer(*addr)

	sm, err := sm.NewStateMachine(l.RbMap)
	if err != nil {
		log.WithError(err).Fatal("cannot create state machine")
	}

	// relay select signals to channel stopper
	chSignal := make(chan os.Signal, 1)
	signal.Notify(chSignal, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	chErrors := make(chan error, 2)

	go func() {
		if err := hs.Run(); err != nil {
			chErrors <- err
		}
	}()
	go func() {
		if err := sm.Run(); err != nil {
			chErrors <- err
		}
	}()

	select {
	case err := <-chErrors: // stop because of error in a goroutine
		log.WithError(err).Error("stop")
	case sig := <-chSignal: // stop because of signal
		log.WithFields(logrus.Fields{"signal": sig}).Info("stop")
	}

	if err := sm.Stop(); err != nil {
		log.WithError(err).Error("cannot stop state machine")
	}
	ctx := context.Background()
	if err := hs.Stop(ctx); err != nil {
		log.WithError(err).Error("cannot stop HTTP server")
	}
}
