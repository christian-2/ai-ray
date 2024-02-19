package info

import (
	"net/http"

	"github.com/christian-2/ai-ray/pkg/module"
)

type Info struct {
	module.AbstractModule
}

func NewModule() (*Info, error) {
	return &Info{}, nil
}

func (*Info) Start() error {
	return nil
}

func (*Info) Stop() error {
	return nil
}

func ServeHTTP(http.ResponseWriter, *http.Request) {
	// TODO
}
