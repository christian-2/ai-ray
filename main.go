package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/christian-2/ai-ray/pkg/common"
	"github.com/christian-2/ai-ray/pkg/core"
	"github.com/christian-2/ai-ray/pkg/logger"
	"github.com/christian-2/ai-ray/pkg/module"
	"github.com/christian-2/ai-ray/pkg/module/info"
	"github.com/christian-2/ai-ray/pkg/module/mem"
	"github.com/christian-2/ai-ray/pkg/module/torch"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	KERNEL_RELEASES string // injected as build-time variable

	log = logger.GetLogger()

	rootCmd = &cobra.Command{
		Use:   "ai-ray",
		Short: "ai-ray: AI observability and enforcement",
		Run: func(cmd *cobra.Command, args []string) {
			run()
		}}
)

func init() {
	rootCmd.Flags().BoolVar(&common.Info, "info", false,
		"enable module info")
	rootCmd.Flags().BoolVar(&common.Mem, "mem", false,
		"enable module mem")
	rootCmd.Flags().BoolVar(&common.Torch, "torch", false,
		"enable module torch")
	rootCmd.Flags().StringVar(&common.Model, "model", "",
		"filename of AI model")
	rootCmd.Flags().StringVar(&common.Addr, "addr", ":9090",
		"binding address")
	rootCmd.Flags().BoolVar(&common.Debug, "debug", false,
		"debugging information")

	rootCmd.MarkFlagsRequiredTogether("mem", "model")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.WithError(err).Fatal("cannot execute command")
	}
}

func run() {

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

	// load modules' eBPF programss and maps

	mm := make([]module.Module, 0, 3)
	if common.Info {
		m, err := info.NewModule()
		if err != nil {
			log.WithError(err).Fatal("cannot create module info")
		} else {
			mm = append(mm, m)
		}
	}
	if common.Mem {
		m, err := mem.NewModule("bpf/mem/mem.o")
		if err != nil {
			log.WithError(err).Fatal("cannot create module mem")
		} else {
			mm = append(mm, m)
		}
	}
	if common.Torch {
		m, err := torch.NewModule("bpf/torch/torch.o")
		if err != nil {
			log.WithError(err).Fatal("cannot create module torch")
		} else {
			mm = append(mm, m)
		}
	}

	if len(mm) == 0 {
		log.Info("no modules")
		os.Exit(0)
	}

	for _, m := range mm {
		if err := m.LoadAndAttach(); err != nil {
			log.WithError(err).Fatal("Load")
		}
	}

	// relay select signals to channel stopper

	chSignal := make(chan os.Signal, 1)
	signal.Notify(chSignal, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	chErrors := make(chan error, 1+len(mm))

	// start HTTP server in one goroutine

	srv := &http.Server{Addr: common.Addr}

	go func() {
		log.WithFields(logrus.Fields{
			"addr": srv.Addr}).
			Info("start HTTP server")
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			chErrors <- err
		}
	}()

	// start modules in one gorouting each

	for _, m := range mm {
		go func() {
			if err := m.Start(); err != nil {
				chErrors <- err
			}
		}()
	}

	// wait until termination

	select {
	case err := <-chErrors: // stop because of error in a goroutine
		log.WithError(err).Error("stop")
	case sig := <-chSignal: // stop because of signal
		log.WithFields(logrus.Fields{"signal": sig}).Info("stop")
	}

	// stop and unload modules

	for _, m := range mm {
		if err := m.Stop(); err != nil {
			log.WithError(err).Error("cannot stop module")
		}
		if err := m.Unload(); err != nil {
			log.WithError(err).Error("cannot unload module")
		}
	}

	// stop HTTP server

	ctx := context.Background()
	if err := srv.Shutdown(ctx); err != nil {
		log.WithError(err).Error("cannot stop HTTP server")
	}
}
