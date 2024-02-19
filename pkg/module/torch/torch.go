package torch

import (
	"net/http"

	"github.com/christian-2/ai-ray/pkg/module"
)

type Torch struct {
	module.AbstractModule
}

func NewModule(objFile string) (*Torch, error) {
	s := module.ModuleSpec{ObjFile: objFile}
	a := module.AbstractModule{Spec: s}
	return &Torch{AbstractModule: a}, nil
}

func (*Torch) Start() error {
	return nil // TODO
}

func (*Torch) Stop() error {
	return nil // TODO
}

func ServeHTTP(http.ResponseWriter, *http.Request) {
	// TODO
}
