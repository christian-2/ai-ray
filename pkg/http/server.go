package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/christian-2/ai-ray/pkg/logger"
	"github.com/sirupsen/logrus"
)

var (
	log = logger.GetLogger()
)

type httpServer struct {
	srv *http.Server
}

func NewHttpServer(addr string) *httpServer {
	srv := &http.Server{Addr: addr}

	return &httpServer{srv: srv}
}

func (hs *httpServer) Run() error {
	log.WithFields(logrus.Fields{
		"addr": hs.srv.Addr}).
		Info("start HTTP server")
	err := hs.srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server failed: %w", err)
	} else {
		return nil
	}
}

func (hs *httpServer) Stop(ctx context.Context) error {
	return hs.srv.Shutdown(ctx)
}
